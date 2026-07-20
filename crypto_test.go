package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
)

// testKey は決まった内容の 32 バイト鍵を作る。
func testKey(t *testing.T, fill byte) []byte {
	t.Helper()
	return bytes.Repeat([]byte{fill}, MasterKeyBytes)
}

// flipByte は i バイト目の 1 ビットだけを反転した複製を返す。改竄検出の
// テストで使う。元のスライスは変更しない。
func flipByte(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0x01
	return out
}

// 暗号文の形式を決める定数は、一度でも DB に書いたら二度と変えられない
// (既存の暗号文が全て復号できなくなる)。定数同士を比較しても「変更した」
// ことを検出できないので、DESIGN §6 に書かれたリテラル値と突き合わせる。
func TestCryptoFormatConstants(t *testing.T) {
	t.Parallel()

	t.Run("aad strings", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name, got, want string
		}{
			{"keyring aad", keyringAADString, "hokora/keyring/v1"},
			{"item aad prefix", itemAADPrefix, "hokora/item/v1"},
		}
		for _, tt := range tests {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q (DESIGN §6.3 / §6.4)", tt.name, tt.got, tt.want)
			}
		}
	})

	t.Run("lengths", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			got, want int
		}{
			{"master key bytes", MasterKeyBytes, 32},
			{"kdf salt bytes", kdfSaltBytes, 16},
			{"nonce bytes", nonceBytes, 12},
			{"item aad prefix length", len(itemAADPrefix), 14},
			{"item aad length", itemAADLen, 14 + 8 + 4 + 4},
		}
		for _, tt := range tests {
			if tt.got != tt.want {
				t.Errorf("%s = %d, want %d (DESIGN §6)", tt.name, tt.got, tt.want)
			}
		}
	})

	// argon2 のパラメータを弱める変更は、テストが通ったまま防御だけを下げる。
	t.Run("argon2 parameters", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name      string
			got, want uint32
		}{
			{"time", argon2Time, 3},
			{"memory (KiB)", argon2Memory, 64 * 1024},
			{"threads", uint32(argon2Threads), 4},
		}
		for _, tt := range tests {
			if tt.got != tt.want {
				t.Errorf("argon2 %s = %d, want %d (DESIGN §6.2)", tt.name, tt.got, tt.want)
			}
		}
	})
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	key := testKey(t, 0xA5)
	aad := []byte("hokora/test/v1")

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("s3cr3t")},
		{"utf8", []byte("パスワード")},
		{"binary", []byte{0x00, 0xff, 0x00, 0xfe}},
		{"max size", bytes.Repeat([]byte("a"), MaxSecretValueBytes)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ciphertext, nonce, err := sealBytes(key, tt.plaintext, aad)
			if err != nil {
				t.Fatalf("sealBytes: %v", err)
			}
			if len(nonce) != nonceBytes {
				t.Errorf("nonce length = %d, want %d", len(nonce), nonceBytes)
			}
			// nonce を暗号文に連結していないこと(スキーマが別カラムで持つ)。
			if bytes.Contains(ciphertext, nonce) {
				t.Error("ciphertext contains the nonce")
			}
			if len(tt.plaintext) > 0 && bytes.Contains(ciphertext, tt.plaintext) {
				t.Error("ciphertext contains the plaintext")
			}

			got, err := openBytes(key, nonce, ciphertext, aad)
			if err != nil {
				t.Fatalf("openBytes: %v", err)
			}
			if !bytes.Equal(got, tt.plaintext) {
				t.Errorf("round trip mismatch: got %d bytes, want %d", len(got), len(tt.plaintext))
			}
		})
	}
}

// 誤った鍵・AAD・nonce・改竄された暗号文のいずれでも復号は失敗し、
// どれが原因かを区別しない ErrDecrypt が返る。
func TestOpenBytesRejectsTamperedInput(t *testing.T) {
	t.Parallel()

	key := testKey(t, 0x01)
	aad := []byte("hokora/test/v1")
	plaintext := []byte("s3cr3t")

	ciphertext, nonce, err := sealBytes(key, plaintext, aad)
	if err != nil {
		t.Fatalf("sealBytes: %v", err)
	}

	tests := []struct {
		name       string
		key        []byte
		nonce      []byte
		ciphertext []byte
		aad        []byte
	}{
		{"wrong key", testKey(t, 0x02), nonce, ciphertext, aad},
		{"key one bit off", flipByte(key, 31), nonce, ciphertext, aad},
		{"wrong nonce", key, flipByte(nonce, 0), ciphertext, aad},
		{"short nonce", key, nonce[:nonceBytes-1], ciphertext, aad},
		// 長い nonce も弾く。GCM は 12 バイト以外を GHASH で畳み込んで受け付けて
		// しまうので、長さ検査が「短すぎる」だけを見ていると通ってしまう。
		{"long nonce", key, append(bytes.Clone(nonce), 0x00), ciphertext, aad},
		{"empty nonce", key, nil, ciphertext, aad},
		{"tampered ciphertext", key, nonce, flipByte(ciphertext, 0), aad},
		{"tampered tag", key, nonce, flipByte(ciphertext, len(ciphertext)-1), aad},
		{"truncated ciphertext", key, nonce, ciphertext[:len(ciphertext)-1], aad},
		// 認証タグ(16 バイト)より短い入力。GCM 実装の境界。
		{"shorter than the tag", key, nonce, ciphertext[:8], aad},
		{"empty ciphertext", key, nonce, nil, aad},
		{"wrong aad", key, nonce, ciphertext, []byte("hokora/test/v2")},
		{"empty aad", key, nonce, ciphertext, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := openBytes(tt.key, tt.nonce, tt.ciphertext, tt.aad)
			if !errors.Is(err, ErrDecrypt) {
				t.Fatalf("error = %v, want ErrDecrypt", err)
			}
			if got != nil {
				t.Error("plaintext returned despite failure")
			}
		})
	}
}

// 鍵長の誤りは ErrDecrypt ではなく実装のバグなので、区別できるエラーにする。
func TestSealOpenRejectBadKeyLength(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 16, 31, 33, 64} {
		key := bytes.Repeat([]byte{0x01}, n)
		if _, _, err := sealBytes(key, []byte("x"), nil); err == nil {
			t.Errorf("sealBytes with %d-byte key: want error", n)
		}
		if _, err := openBytes(key, make([]byte, nonceBytes), []byte("x"), nil); err == nil {
			t.Errorf("openBytes with %d-byte key: want error", n)
		} else if errors.Is(err, ErrDecrypt) {
			t.Errorf("openBytes with %d-byte key: got ErrDecrypt, want a key length error", n)
		}
	}
}

// nonce は毎回 crypto/rand で生成される。同じ鍵・同じ平文でも暗号文が一致しない。
func TestSealBytesNonceIsUnique(t *testing.T) {
	t.Parallel()

	key := testKey(t, 0x7f)
	const iterations = 256

	nonces := make(map[string]struct{}, iterations)
	ciphertexts := make(map[string]struct{}, iterations)
	for i := range iterations {
		ciphertext, nonce, err := sealBytes(key, []byte("same plaintext"), nil)
		if err != nil {
			t.Fatalf("sealBytes #%d: %v", i, err)
		}
		if _, dup := nonces[string(nonce)]; dup {
			t.Fatalf("nonce reused at iteration %d", i)
		}
		nonces[string(nonce)] = struct{}{}
		if _, dup := ciphertexts[string(ciphertext)]; dup {
			t.Fatalf("ciphertext repeated at iteration %d", i)
		}
		ciphertexts[string(ciphertext)] = struct{}{}
	}
}

func TestGenerateKey(t *testing.T) {
	t.Parallel()

	const iterations = 64
	seen := make(map[string]struct{}, iterations)
	for i := range iterations {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey #%d: %v", i, err)
		}
		if len(key) != MasterKeyBytes {
			t.Fatalf("key length = %d, want %d", len(key), MasterKeyBytes)
		}
		if bytes.Equal(key, make([]byte, MasterKeyBytes)) {
			t.Fatal("key is all zeros")
		}
		if _, dup := seen[string(key)]; dup {
			t.Fatalf("key repeated at iteration %d", i)
		}
		seen[string(key)] = struct{}{}
	}
}

func TestZero(t *testing.T) {
	t.Parallel()

	b := bytes.Repeat([]byte{0xff}, 64)
	Zero(b)
	if !bytes.Equal(b, make([]byte, 64)) {
		t.Error("Zero left non-zero bytes")
	}

	// nil / 空でも落ちない。
	Zero(nil)
	Zero([]byte{})
}

// Zero が消すのは「渡されたスライスの len 分だけ」である。
//
// これは呼び出し側の責務に直結する。`buf[:n]` を渡しても cap の残りは
// 残るし、逆に他のスライスと backing array を共有していればそちらも消える。
// best effort である以前に、範囲そのものを取り違えると鍵素材が残る。
func TestZeroClearsOnlyTheSliceRange(t *testing.T) {
	t.Parallel()

	t.Run("subslice", func(t *testing.T) {
		t.Parallel()

		buf := bytes.Repeat([]byte{0xff}, 32)
		Zero(buf[8:16])

		want := bytes.Repeat([]byte{0xff}, 32)
		clear(want[8:16])
		if !bytes.Equal(buf, want) {
			t.Errorf("Zero cleared the wrong range: %x", buf)
		}
	})

	t.Run("len shorter than cap", func(t *testing.T) {
		t.Parallel()

		// DecodeMasterKey のように buf[:n] を返す関数の戻り値を消しても、
		// n を超えた領域は残る。
		buf := bytes.Repeat([]byte{0xff}, 32)
		head := buf[:16]
		Zero(head)

		if !bytes.Equal(buf[:16], make([]byte, 16)) {
			t.Error("Zero left non-zero bytes within the slice")
		}
		if !bytes.Equal(buf[16:], bytes.Repeat([]byte{0xff}, 16)) {
			t.Error("Zero reached beyond len; the test's assumption about cap is wrong")
		}
	})

	t.Run("alias", func(t *testing.T) {
		t.Parallel()

		// 同じ backing array を指すスライスを消せば、元のスライスも消える。
		buf := bytes.Repeat([]byte{0xff}, 32)
		alias := buf
		Zero(alias)

		if !bytes.Equal(buf, make([]byte, 32)) {
			t.Error("zeroing an alias did not clear the original")
		}
	})
}

// ---- MK の正規化と検証(DESIGN §6.1) ----

func TestDecodeMasterKey(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x2a}, MasterKeyBytes)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	// 末尾ビットが 0 でない非正規なエンコード。Strict() が弾く。
	// 32 バイトは 43 文字にエンコードされ、最終文字の下位 2 ビットは余りである。
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	lastIndex := strings.IndexByte(alphabet, encoded[42])
	if lastIndex < 0 {
		t.Fatalf("test setup: %q is not in the base64url alphabet", encoded[42])
	}
	nonCanonical := encoded[:42] + string(alphabet[lastIndex|0x03])
	if nonCanonical == encoded {
		t.Fatal("test setup: non-canonical encoding matches the canonical one")
	}
	// 余りビットを無視するデコーダなら通る文字列であること(Strict() の効果を見る)。
	if _, err := base64.RawURLEncoding.DecodeString(nonCanonical); err != nil {
		t.Fatalf("test setup: non-strict decode failed: %v", err)
	}

	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{"plain", encoded, key},
		{"trailing LF", encoded + "\n", key},
		{"trailing CRLF", encoded + "\r\n", key},

		// 除去するのは末尾の単一改行のみ。空白の trim はしない。
		{"trailing double LF", encoded + "\n\n", nil},
		{"trailing space", encoded + " ", nil},
		{"leading space", " " + encoded, nil},
		{"trailing tab", encoded + "\t", nil},
		{"inner LF", encoded[:20] + "\n" + encoded[20:], nil},
		{"leading LF", "\n" + encoded, nil},
		{"CR only", encoded + "\r", nil},
		// LF を 1 つ落としても CR が残る。除去は「末尾の LF、その直前の CR」の
		// 順であって、末尾の改行類をまとめて刈るのではない。
		{"trailing CRLF then LF", encoded + "\r\n\n", nil},
		{"trailing LF then CR", encoded + "\n\r", nil},
		{"embedded NUL", encoded[:20] + "\x00" + encoded[20:], nil},

		{"empty", "", nil},
		{"newline only", "\n", nil},
		{"padded base64", base64.URLEncoding.EncodeToString(key), nil},
		{"standard base64 alphabet", base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{0xff}, MasterKeyBytes)), nil},
		{"not base64", "この鍵はだめ", nil},
		{"31 bytes", base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x2a}, MasterKeyBytes-1)), nil},
		{"33 bytes", base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x2a}, MasterKeyBytes+1)), nil},
		// 長さ検査が「32 バイト未満を弾く」だけになっていないこと。
		{"64 bytes", base64.RawURLEncoding.EncodeToString(
			bytes.Repeat([]byte{0x2a}, MasterKeyBytes*2)), nil},
		// base64 を経由せず生の 32 バイトを流し込む運用ミス。長さだけを見る
		// 実装なら通ってしまう。
		{"raw key bytes", string(key), nil},
		{"non-canonical trailing bits", nonCanonical, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := DecodeMasterKey([]byte(tt.input))
			if tt.want == nil {
				if !errors.Is(err, ErrInvalidMasterKey) {
					t.Fatalf("error = %v, want ErrInvalidMasterKey", err)
				}
				if got != nil {
					t.Error("key returned despite failure")
				}
				// エラーが入力を反映していないこと(AGENTS.md ルール 20)。
				if tt.input != "" && bytes.Contains([]byte(err.Error()), []byte(tt.input)) {
					t.Errorf("error message contains the input: %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeMasterKey: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("decoded %d bytes, want %d", len(got), len(tt.want))
			}
		})
	}
}

// DecodeMasterKey は入力バッファを書き換えない(呼び出し側が消せるように)。
func TestDecodeMasterKeyDoesNotModifyInput(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0x11}, MasterKeyBytes)
	raw := []byte(EncodeMasterKey(key) + "\n")
	before := bytes.Clone(raw)

	got, err := DecodeMasterKey(raw)
	if err != nil {
		t.Fatalf("DecodeMasterKey: %v", err)
	}
	if !bytes.Equal(raw, before) {
		t.Error("DecodeMasterKey modified its input")
	}

	// 戻り値が入力と backing array を共有していないこと。共有していると、
	// 呼び出し側が「読み込みバッファ」と「MK」のどちらを先に Zero しても、
	// もう一方が意図せず消える(あるいは消したつもりが消えていない)。
	Zero(got)
	if !bytes.Equal(raw, before) {
		t.Error("zeroing the decoded key modified the input buffer")
	}
}

func TestEncodeMasterKeyRoundTrip(t *testing.T) {
	t.Parallel()

	for range 32 {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		encoded := EncodeMasterKey(key)
		// 運用者がコピー&ペーストする値なので、パディングや改行を含まない。
		if bytes.ContainsAny([]byte(encoded), "=+/\r\n ") {
			t.Fatalf("encoded key contains an unexpected character: %q", encoded)
		}
		// 32 バイトのパディングなし base64 は必ず 43 文字。運用者が
		// 「途中で切れていないか」を目視で確かめる拠り所になる。
		if len(encoded) != 43 {
			t.Fatalf("encoded length = %d, want 43", len(encoded))
		}
		got, err := DecodeMasterKey([]byte(encoded))
		if err != nil {
			t.Fatalf("DecodeMasterKey: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Fatal("round trip mismatch")
		}
	}
}

// ---- KEK の導出 ----

func TestDeriveKEK(t *testing.T) {
	t.Parallel()

	mk := testKey(t, 0x01)
	salt := bytes.Repeat([]byte{0x02}, kdfSaltBytes)

	kek, err := DeriveKEK(mk, salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if len(kek) != MasterKeyBytes {
		t.Fatalf("kek length = %d, want %d", len(kek), MasterKeyBytes)
	}
	if bytes.Equal(kek, mk) {
		t.Fatal("kek equals the master key")
	}

	// 決定的であること(同じ MK と salt なら unseal のたびに同じ KEK)。
	again, err := DeriveKEK(mk, salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if !bytes.Equal(kek, again) {
		t.Fatal("DeriveKEK is not deterministic")
	}

	// MK が違えば KEK も違う。salt が違っても違う。
	otherMK, err := DeriveKEK(testKey(t, 0x03), salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if bytes.Equal(kek, otherMK) {
		t.Fatal("different master keys produced the same kek")
	}
	otherSalt, err := DeriveKEK(mk, bytes.Repeat([]byte{0x04}, kdfSaltBytes))
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if bytes.Equal(kek, otherSalt) {
		t.Fatal("different salts produced the same kek")
	}
}

func TestDeriveKEKRejectsBadLengths(t *testing.T) {
	t.Parallel()

	salt := bytes.Repeat([]byte{0x02}, kdfSaltBytes)

	for _, n := range []int{0, 16, 31, 33} {
		_, err := DeriveKEK(bytes.Repeat([]byte{0x01}, n), salt)
		if !errors.Is(err, ErrInvalidMasterKey) {
			t.Errorf("DeriveKEK with %d-byte mk: error = %v, want ErrInvalidMasterKey", n, err)
		}
	}
	for _, n := range []int{0, 8, 15, 17, 32} {
		if _, err := DeriveKEK(testKey(t, 0x01), bytes.Repeat([]byte{0x02}, n)); err == nil {
			t.Errorf("DeriveKEK with %d-byte salt: want error", n)
		}
	}
}

// ---- itemAAD(DESIGN §6.4) ----

func TestItemAAD(t *testing.T) {
	t.Parallel()

	aad, err := itemAAD(1, 2, 3)
	if err != nil {
		t.Fatalf("itemAAD: %v", err)
	}

	want := append([]byte(itemAADPrefix), []byte{
		0, 0, 0, 0, 0, 0, 0, 1, // uint64be(item_id)
		0, 0, 0, 2, // uint32be(version)
		0, 0, 0, 3, // uint32be(dek_version)
	}...)
	if !bytes.Equal(aad, want) {
		t.Fatalf("aad = %x, want %x", aad, want)
	}
	if len(itemAADPrefix) != 14 {
		t.Fatalf("prefix length = %d, want 14", len(itemAADPrefix))
	}
	if len(aad) != itemAADLen {
		t.Fatalf("aad length = %d, want %d", len(aad), itemAADLen)
	}
}

func TestItemAADRange(t *testing.T) {
	t.Parallel()

	const maxU32 = int64(math.MaxUint32)

	tests := []struct {
		name                        string
		itemID, version, dekVersion int64
		wantErr                     bool
	}{
		{name: "minimum", itemID: 1, version: 1, dekVersion: 1},
		{name: "uint32 max", itemID: 1, version: maxU32, dekVersion: maxU32},
		{name: "large item id", itemID: math.MaxInt64, version: 1, dekVersion: 1},

		{name: "item id zero", itemID: 0, version: 1, dekVersion: 1, wantErr: true},
		{name: "item id negative", itemID: -1, version: 1, dekVersion: 1, wantErr: true},
		{name: "version zero", itemID: 1, version: 0, dekVersion: 1, wantErr: true},
		{name: "version negative", itemID: 1, version: -1, dekVersion: 1, wantErr: true},
		{name: "version 2^32", itemID: 1, version: maxU32 + 1, dekVersion: 1, wantErr: true},
		{name: "version 2^33", itemID: 1, version: 1 << 33, dekVersion: 1, wantErr: true},
		// 切り捨てが起きると version=1 と同じ AAD になる組み合わせ。
		{name: "version 2^32+1", itemID: 1, version: maxU32 + 2, dekVersion: 1, wantErr: true},
		{name: "dek version zero", itemID: 1, version: 1, dekVersion: 0, wantErr: true},
		{name: "dek version negative", itemID: 1, version: 1, dekVersion: -1, wantErr: true},
		{name: "dek version 2^32", itemID: 1, version: 1, dekVersion: maxU32 + 1, wantErr: true},
		{name: "dek version 2^32+1", itemID: 1, version: 1, dekVersion: maxU32 + 2, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aad, err := itemAAD(tt.itemID, tt.version, tt.dekVersion)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("itemAAD(%d, %d, %d) = %x, want error",
						tt.itemID, tt.version, tt.dekVersion, aad)
				}
				if aad != nil {
					t.Error("aad returned despite failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("itemAAD: %v", err)
			}
			if len(aad) != itemAADLen {
				t.Fatalf("aad length = %d, want %d", len(aad), itemAADLen)
			}
		})
	}
}

// itemAAD の範囲検査が守っている性質そのものを直接書く。
//
// version / dek_version の範囲検査を消すと、int64 → uint32 の切り捨てによって
// **別の行が同じ AAD を持つ**。AAD が同じなら、片方の暗号文をもう片方の行に
// 移し替えても復号でき、混線の検出という AAD の存在意義(DESIGN §6.4)が消える。
// 「エラーになること」だけを見るテストでは、この因果が読み取れない。
func TestItemAADRangeCheckPreventsCollision(t *testing.T) {
	t.Parallel()

	const maxU32 = int64(math.MaxUint32)

	tests := []struct {
		name                        string
		itemID, version, dekVersion int64
		// 切り捨てが起きた場合に衝突する相手。
		collidesWith [3]int64
	}{
		{"version wraps to 1", 1, maxU32 + 2, 1, [3]int64{1, 1, 1}},
		{"version wraps to 2", 1, maxU32 + 3, 1, [3]int64{1, 2, 1}},
		{"dek version wraps to 1", 1, 1, maxU32 + 2, [3]int64{1, 1, 1}},
		{"both wrap", 1, maxU32 + 2, maxU32 + 2, [3]int64{1, 1, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// 前提: 下位 32 ビットが衝突相手と一致していること。定数畳み込みで
			// コンパイルエラーにならないよう、剰余で表現する。
			const mod = int64(1) << 32
			if tt.version%mod != tt.collidesWith[1] || tt.dekVersion%mod != tt.collidesWith[2] {
				t.Fatalf("test setup: (%d, %d) does not truncate to %v",
					tt.version, tt.dekVersion, tt.collidesWith)
			}

			want, err := itemAAD(tt.collidesWith[0], tt.collidesWith[1], tt.collidesWith[2])
			if err != nil {
				t.Fatalf("itemAAD%v: %v", tt.collidesWith, err)
			}

			aad, err := itemAAD(tt.itemID, tt.version, tt.dekVersion)
			if err == nil {
				if bytes.Equal(aad, want) {
					t.Fatalf("aad for (%d, %d, %d) collides with %v",
						tt.itemID, tt.version, tt.dekVersion, tt.collidesWith)
				}
				t.Fatalf("itemAAD(%d, %d, %d) = %x, want an out-of-range error",
					tt.itemID, tt.version, tt.dekVersion, aad)
			}
		})
	}
}

// AAD は固定幅なので、どの成分が違っても必ず別の AAD になる。
// 区切り文字で連結していた初期案は、ここで衝突しうる(DESIGN §6.4)。
func TestItemAADIsUnambiguous(t *testing.T) {
	t.Parallel()

	ids := []int64{1, 2, 10, 11, 100, 0x0102030405060708, math.MaxInt64}
	versions := []int64{1, 2, 10, 11, 0x01020304, math.MaxUint32}

	seen := make(map[string][3]int64)
	for _, id := range ids {
		for _, version := range versions {
			for _, dekVersion := range versions {
				aad, err := itemAAD(id, version, dekVersion)
				if err != nil {
					t.Fatalf("itemAAD(%d, %d, %d): %v", id, version, dekVersion, err)
				}
				if len(aad) != itemAADLen {
					t.Fatalf("aad length = %d, want %d (fixed width)", len(aad), itemAADLen)
				}
				key := string(aad)
				if prev, dup := seen[key]; dup {
					t.Fatalf("aad collision: (%d, %d, %d) and %v",
						id, version, dekVersion, prev)
				}
				seen[key] = [3]int64{id, version, dekVersion}
			}
		}
	}
}

// AAD の各成分が実際に復号の可否を左右すること。item_id / version /
// dek_version のそれぞれについて確認する(ROADMAP M2 完了条件)。
func TestItemAADBindsCiphertext(t *testing.T) {
	t.Parallel()

	dek := testKey(t, 0x5a)
	plaintext := []byte("postgres://user:pass@localhost/db")

	const (
		itemID     = int64(42)
		version    = int64(7)
		dekVersion = int64(3)
	)
	aad, err := itemAAD(itemID, version, dekVersion)
	if err != nil {
		t.Fatalf("itemAAD: %v", err)
	}
	ciphertext, nonce, err := sealBytes(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("sealBytes: %v", err)
	}

	got, err := openBytes(dek, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("openBytes with the correct aad: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip mismatch")
	}

	tests := []struct {
		name                        string
		itemID, version, dekVersion int64
	}{
		{"different item", itemID + 1, version, dekVersion},
		{"different version", itemID, version + 1, dekVersion},
		{"previous version", itemID, version - 1, dekVersion},
		{"different dek version", itemID, version, dekVersion + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			otherAAD, err := itemAAD(tt.itemID, tt.version, tt.dekVersion)
			if err != nil {
				t.Fatalf("itemAAD: %v", err)
			}
			if _, err := openBytes(dek, nonce, ciphertext, otherAAD); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("error = %v, want ErrDecrypt", err)
			}
		})
	}
}

// ---- 入力の不変性とエラーメッセージ ----

// sealBytes / openBytes は渡されたバッファを書き換えず、戻り値と backing array
// を共有しない。
//
// AEAD の実装では出力先に入力スライスを再利用する最適化がよく行われる
// (`gcm.Seal(plaintext[:0], ...)` の形)。それをやると、呼び出し側が握っている
// 平文が暗号文に化けたり、逆に暗号文バッファのつもりで平文を DB に書いたりする。
func TestSealOpenDoNotAliasInputs(t *testing.T) {
	t.Parallel()

	key := testKey(t, 0x3c)
	plaintext := []byte("s3cr3t value")
	aad := []byte("hokora/test/v1")

	keyBefore := bytes.Clone(key)
	plaintextBefore := bytes.Clone(plaintext)
	aadBefore := bytes.Clone(aad)

	// この暗号文は破壊して捨てるので、nonce は使わない。
	scratch, _, err := sealBytes(key, plaintext, aad)
	if err != nil {
		t.Fatalf("sealBytes: %v", err)
	}
	if !bytes.Equal(key, keyBefore) {
		t.Error("sealBytes modified the key")
	}
	if !bytes.Equal(plaintext, plaintextBefore) {
		t.Error("sealBytes modified the plaintext")
	}
	if !bytes.Equal(aad, aadBefore) {
		t.Error("sealBytes modified the aad")
	}

	// 暗号文を潰しても平文が無事であること(backing array を共有していない)。
	clear(scratch)
	if !bytes.Equal(plaintext, plaintextBefore) {
		t.Fatal("ciphertext shares its backing array with the plaintext")
	}

	ciphertext, nonce, err := sealBytes(key, plaintext, aad)
	if err != nil {
		t.Fatalf("sealBytes: %v", err)
	}
	ciphertextBefore := bytes.Clone(ciphertext)
	nonceBefore := bytes.Clone(nonce)

	got, err := openBytes(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("openBytes: %v", err)
	}
	if !bytes.Equal(ciphertext, ciphertextBefore) {
		t.Error("openBytes modified the ciphertext")
	}
	if !bytes.Equal(nonce, nonceBefore) {
		t.Error("openBytes modified the nonce")
	}
	if !bytes.Equal(aad, aadBefore) {
		t.Error("openBytes modified the aad")
	}

	// 復号結果を Zero しても暗号文は残る。unseal 後に平文だけを消す運用が成立する。
	Zero(got)
	if !bytes.Equal(ciphertext, ciphertextBefore) {
		t.Error("plaintext shares its backing array with the ciphertext")
	}
}

// エラーメッセージに鍵素材・平文を含めない(AGENTS.md ルール 19-21)。
//
// 長さ違反のエラーは値ではなく長さだけを言うべきで、`%v` や `%q` で
// バッファそのものを埋め込む書き方に変わったらここで落ちる。
func TestErrorMessagesDoNotLeakSecrets(t *testing.T) {
	t.Parallel()

	// 16 進・base64 のどちらで埋め込まれても検出できるよう、両方を探す。
	contains := func(t *testing.T, msg string, secret []byte) bool {
		t.Helper()
		return strings.Contains(msg, string(secret)) ||
			strings.Contains(msg, hex.EncodeToString(secret)) ||
			strings.Contains(msg, base64.RawURLEncoding.EncodeToString(secret))
	}

	badKey := bytes.Repeat([]byte{0xab}, MasterKeyBytes-1)
	badSalt := bytes.Repeat([]byte{0xcd}, kdfSaltBytes+1)
	plaintext := []byte("s3cr3t value")

	tests := []struct {
		name    string
		err     error
		secrets [][]byte
	}{
		{
			name: "newGCM with a short key",
			err: func() error {
				_, err := newGCM(badKey)
				return err
			}(),
			secrets: [][]byte{badKey},
		},
		{
			name: "sealBytes with a short key",
			err: func() error {
				_, _, err := sealBytes(badKey, plaintext, nil)
				return err
			}(),
			secrets: [][]byte{badKey, plaintext},
		},
		{
			name: "openBytes with a short key",
			err: func() error {
				_, err := openBytes(badKey, make([]byte, nonceBytes), []byte("x"), nil)
				return err
			}(),
			secrets: [][]byte{badKey},
		},
		{
			name: "DeriveKEK with a short master key",
			err: func() error {
				_, err := DeriveKEK(badKey, bytes.Repeat([]byte{0x02}, kdfSaltBytes))
				return err
			}(),
			secrets: [][]byte{badKey},
		},
		{
			// salt は秘密ではないが、ここに値を書く実装は MK にも同じことをしうる。
			name: "DeriveKEK with a long salt",
			err: func() error {
				_, err := DeriveKEK(testKey(t, 0x01), badSalt)
				return err
			}(),
			secrets: [][]byte{badSalt},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.err == nil {
				t.Fatal("want an error")
			}
			for _, secret := range tt.secrets {
				if contains(t, tt.err.Error(), secret) {
					t.Errorf("error message leaks %d bytes of input: %v", len(secret), tt.err)
				}
			}
		})
	}
}
