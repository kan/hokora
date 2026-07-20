package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"

	"golang.org/x/crypto/argon2"
)

// 鍵とノンスの長さ(DESIGN §6)。
const (
	// MasterKeyBytes は MK / KEK / DEK 共通の鍵長である(AES-256)。
	MasterKeyBytes = 32
	// kdfSaltBytes は MK → KEK の導出に使う salt の長さである。
	kdfSaltBytes = 16
	// nonceBytes は AES-GCM の標準 nonce 長である。GCM は 12 バイト以外も
	// 受け付けるが、その場合は内部で GHASH による再導出が入るため使わない。
	nonceBytes = 12
)

// argon2id のパラメータ(DESIGN §6.2)。
//
// この argon2 が走るのは unseal / rotate-master のみである。Machine API の
// 認証経路では使わない(AGENTS.md ルール 7。client_secret は crypto/rand 由来の
// 高エントロピー値なので SHA-256 で足り、argon2 は DoS 増幅器にしかならない)。
const (
	argon2Time    uint32 = 3
	argon2Memory  uint32 = 64 * 1024 // KiB = 64 MB
	argon2Threads uint8  = 4
)

// AAD の固定プレフィックス(DESIGN §6.3 / §6.4)。
const (
	keyringAADString = "hokora/keyring/v1"
	itemAADPrefix    = "hokora/item/v1" // 14 バイト
)

// keyringAAD は DEK のラップに使う AAD である。呼び出し側が書き換えられない
// よう、共有スライスではなく関数で毎回作る。
func keyringAAD() []byte { return []byte(keyringAADString) }

var (
	// ErrInvalidMasterKey は MK の形式が不正であることを示す。
	//
	// 「長さが違う」「base64 が壊れている」を呼び出し側に区別させない。
	// 詳細を返しても運用上の助けにならない一方、入力の性質を漏らすため。
	ErrInvalidMasterKey = errors.New("invalid master key")

	// ErrDecrypt は AEAD の認証に失敗したことを示す。誤った鍵・改竄・
	// AAD の不一致を区別しない(区別すると攻撃者に情報を与える)。
	ErrDecrypt = errors.New("decryption failed")
)

// Zero はバイト列をゼロで上書きする。
//
// **best effort である。** Go のランタイムは GC やスタックの拡張に伴って
// バイト列のコピーを別の場所に残しうるし、そのコピーには手が届かない
// (DESIGN §6.6)。swap への流出は mlockall で塞ぐ(DESIGN §4.2)が、
// core dump / kdump は運用側で止める前提である。
func Zero(b []byte) {
	clear(b)
	// clear の結果は誰にも読まれないため、理屈の上では消去そのものを
	// 消せる。b を生かしておくことで、その最適化を成立しにくくする。
	runtime.KeepAlive(b)
}

// randomBytes は crypto/rand から n バイトを読む。
//
// 鍵・nonce・トークン・セッション ID の生成は全てここを通す
// (AGENTS.md ルール 2。math/rand は暗号用途で使わない)。
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return b, nil
}

// GenerateKey は 32 バイトの鍵を生成する。MK / DEK の生成に使う。
func GenerateKey() ([]byte, error) { return randomBytes(MasterKeyBytes) }

// EncodeMasterKey は MK を運用者に見せる表現(base64url、パディングなし)に
// 変換する。DecodeMasterKey の逆である。
func EncodeMasterKey(mk []byte) string {
	return base64.RawURLEncoding.EncodeToString(mk)
}

// DecodeMasterKey は stdin / HTTP ボディから読んだ MK を正規化・検証する
// (DESIGN §6.1)。
//
//  1. 末尾の単一の LF または CRLF を除去する
//  2. 厳密な base64url(パディングなし)としてデコードする
//  3. 結果が正確に 32 バイトであることを確認する
//
// **前後の空白を trim しない。** 意図しない文字が混入した MK を「たまたま
// 通す」ことを避けるため、除去するのは末尾の単一改行のみとする
// (AGENTS.md ルール 13)。
//
// raw のゼロクリアは呼び出し側の責務である。この関数は自身が確保した
// 中間バッファのみを消す。
func DecodeMasterKey(raw []byte) ([]byte, error) {
	encoded := trimSingleTrailingNewline(raw)

	// encoding/base64 のデコーダは、入力中の CR / LF を黙って読み飛ばす
	// (Strict() でもこの挙動は変わらない。Strict() が見るのは末尾の余りビット
	// だけである)。そのままでは "先頭に改行がある MK"、"途中で折り返された MK"、
	// "末尾に改行が 2 つある MK" が全て通ってしまい、DESIGN §6.1 が要求する
	// 「除去するのは末尾の単一改行のみ」が成立しない。自分で弾く。
	if bytes.ContainsAny(encoded, "\r\n") {
		return nil, ErrInvalidMasterKey
	}

	// Strict() は末尾の余りビットが 0 でない非正規なエンコードを弾く。
	// これがないと、同じ 32 バイトに複数の文字列表現が対応してしまう。
	dec := base64.RawURLEncoding.Strict()

	buf := make([]byte, dec.DecodedLen(len(encoded)))
	n, err := dec.Decode(buf, encoded)
	if err != nil {
		Zero(buf)
		// err は入力の一部(不正な文字とその位置)を含むため、ラップしない。
		return nil, ErrInvalidMasterKey
	}
	if n != MasterKeyBytes {
		Zero(buf)
		return nil, ErrInvalidMasterKey
	}
	return buf[:n], nil
}

// trimSingleTrailingNewline は末尾の LF ひとつ、または CRLF ひとつを取り除く。
// それ以上は取り除かない(空白の trim もしない)。
func trimSingleTrailingNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

// DeriveKEK は MK と salt から KEK を導出する(DESIGN §6.2)。
//
// 呼び出し側は使い終えた KEK を Zero で消すこと。
func DeriveKEK(mk, salt []byte) ([]byte, error) {
	if len(mk) != MasterKeyBytes {
		return nil, ErrInvalidMasterKey
	}
	if len(salt) != kdfSaltBytes {
		return nil, fmt.Errorf("kdf salt must be %d bytes, got %d", kdfSaltBytes, len(salt))
	}
	return argon2.IDKey(mk, salt, argon2Time, argon2Memory, argon2Threads, MasterKeyBytes), nil
}

// sealBytes は AES-256-GCM で plaintext を暗号化し、暗号文と nonce を返す。
//
// nonce は毎回 crypto/rand で生成する(DESIGN §6.5)。同一鍵での nonce 再利用は
// GCM の安全性を根本から壊すため、呼び出し側から nonce を渡せる口は用意しない。
// 暗号文に nonce は連結しない(スキーマが別カラムで持つため)。
func sealBytes(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// openBytes は sealBytes の逆である。認証に失敗したら ErrDecrypt を返す。
//
// 鍵・AAD・暗号文のどれが誤っていたかは区別しない。GCM の認証タグ検証が
// 定数時間で行われるため、値の比較を自前で書く必要はない。
func openBytes(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// newGCM は 32 バイト鍵から AES-256-GCM を作る。
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != MasterKeyBytes {
		return nil, fmt.Errorf("key must be %d bytes, got %d", MasterKeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return gcm, nil
}

// itemAADLen は itemAAD が返す固定長である。
const itemAADLen = len(itemAADPrefix) + 8 + 4 + 4

// itemAAD は secret 値の暗号化に使う AAD を組み立てる(DESIGN §6.4)。
//
//	"hokora/item/v1" || uint64be(item_id) || uint32be(version) || uint32be(dek_version)
//
// **固定幅で連結する。** slug や key を区切り文字で連結する案は、区切り文字の
// 曖昧性・slug の可変性・slug の再利用という 3 つの問題を抱えていた。
//
// DB 側の version / dek_version は int64 である。uint32 への暗黙の切り捨ては
// AAD の一意性を壊すため、範囲外を黙って丸めずエラーにする(AGENTS.md ルール 6)。
// スキーマ側の CHECK 制約と二重で守る。
//
// エラーには ID を含めるが、これらは秘密ではない(値そのものは含めない)。
func itemAAD(itemID, version, dekVersion int64) ([]byte, error) {
	if itemID <= 0 {
		return nil, fmt.Errorf("item_id out of range: %d", itemID)
	}
	if version <= 0 || version > math.MaxUint32 {
		return nil, fmt.Errorf("version out of range: %d", version)
	}
	if dekVersion <= 0 || dekVersion > math.MaxUint32 {
		return nil, fmt.Errorf("dek_version out of range: %d", dekVersion)
	}

	aad := make([]byte, 0, itemAADLen)
	aad = append(aad, itemAADPrefix...)
	aad = binary.BigEndian.AppendUint64(aad, uint64(itemID))
	aad = binary.BigEndian.AppendUint32(aad, uint32(version))
	aad = binary.BigEndian.AppendUint32(aad, uint32(dekVersion))
	return aad, nil
}
