package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// パスワードの制約(DESIGN §7.2)。
const (
	// PasswordMinLen は最小長である。
	PasswordMinLen = 12
	// PasswordMaxLen は最大長である。**超えたら 400 にする。**
	// argon2 は入力長に比例して重くなるため、上限が無いと DoS の口になる。
	PasswordMaxLen = 1024

	passwordSaltBytes = 16
	passwordHashBytes = 32
)

var (
	// ErrPasswordTooShort / ErrPasswordTooLong は入力の長さが範囲外であることを示す。
	// **エラーにパスワードそのものを含めない**(AGENTS.md ルール 20)。
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", PasswordMinLen)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d bytes", PasswordMaxLen)

	// ErrInvalidPasswordHash は保存されているハッシュを解釈できないことを示す。
	ErrInvalidPasswordHash = errors.New("invalid password hash")
)

// ValidatePassword は長さの制約を検査する。
//
// 最大長は **バイト数** で見る。argon2 に渡るのはバイト列であり、そこが
// コストを決めるためである。最小長は文字数で見る(運用者向けの要件)。
func ValidatePassword(password string) error {
	if len(password) > PasswordMaxLen {
		return ErrPasswordTooLong
	}
	if len([]rune(password)) < PasswordMinLen {
		return ErrPasswordTooShort
	}
	return nil
}

// HashPassword は argon2id でパスワードをハッシュし、PHC 文字列を返す。
//
// **保存形式は PHC 文字列である**(DESIGN §7.2):
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
//
// パラメータを保存形式に含めるのは、**将来パラメータを変更しても既存の
// ハッシュを検証できるようにする**ためである。パラメータを定数から読む
// 実装にすると、変更した瞬間に全員がログインできなくなる。
//
// ここで argon2 を使うのは正しい。低エントロピーな秘密(人間のパスワード)が
// 対象であり、到達経路は VPN 内の Web UI に限られ、同時実行は semaphore で
// 制限される(AGENTS.md ルール 7)。
func HashPassword(ctx context.Context, password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}

	salt, err := randomBytes(passwordSaltBytes)
	if err != nil {
		return "", err
	}

	var hash []byte
	if err := withArgon2Slot(ctx, func() error {
		hash = argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, passwordHashBytes)
		return nil
	}); err != nil {
		return "", err
	}
	defer Zero(hash)

	return encodePHC(argon2Params{
		Memory:  argon2Memory,
		Time:    argon2Time,
		Threads: argon2Threads,
	}, salt, hash), nil
}

// VerifyPassword は PHC 文字列に対してパスワードを検証する。
//
// **検証には保存されたパラメータを使う**(定数ではなく)。パラメータを
// 変更した後も、古いハッシュを検証できる必要がある。
//
// 比較は ConstantTimeCompare で行う(AGENTS.md ルール 4)。
func VerifyPassword(ctx context.Context, phc, password string) (bool, error) {
	params, salt, want, err := decodePHC(phc)
	if err != nil {
		return false, err
	}
	defer Zero(want)

	// 長すぎる入力は argon2 に渡さない。ここを通すと、保存側の上限とは
	// 無関係に重い計算を強制できる。
	if len(password) > PasswordMaxLen {
		return false, ErrPasswordTooLong
	}

	// 保存されたハッシュ長で導出する。**範囲外は壊れたハッシュとして扱う**
	// (黙って切り捨てると、別の鍵長で比較して常に不一致になる)。
	// 現実にはあり得ない長さだが、uint32 への変換を検査なしで行わない
	// (AGENTS.md ルール 6 と同じ理由)。
	if len(want) > math.MaxUint32 {
		return false, ErrInvalidPasswordHash
	}
	keyLen := uint32(len(want)) //nolint:gosec // G115: 直前で範囲を検査している

	var got []byte
	if err := withArgon2Slot(ctx, func() error {
		got = argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, keyLen)
		return nil
	}); err != nil {
		return false, err
	}
	defer Zero(got)

	return constantTimeEqual(got, want), nil
}

// argon2Params は PHC 文字列に埋め込むパラメータである。
type argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// encodePHC は PHC 文字列を組み立てる。
func encodePHC(p argon2Params, salt, hash []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// decodePHC は PHC 文字列を解釈する。
//
// **形式が少しでも違えばエラーにする。** 壊れたハッシュを「一致しない」
// として扱うと、DB 破損とパスワード誤りが区別できなくなる。
func decodePHC(phc string) (p argon2Params, salt, hash []byte, err error) {
	// "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>" → 6 要素(先頭は空)
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidPasswordHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	if p.Memory == 0 || p.Time == 0 || p.Threads == 0 {
		return p, nil, nil, ErrInvalidPasswordHash
	}

	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil || len(salt) == 0 {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	if hash, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil || len(hash) == 0 {
		Zero(salt)
		return p, nil, nil, ErrInvalidPasswordHash
	}
	return p, salt, hash, nil
}

// dummyPasswordHash は存在しない username に対する検証相手を返す。
//
// **存在しない username でも argon2 を実行する**(DESIGN §7.2)。早期 return
// すると、応答時間の差で username の存在が分かる。argon2 は数百 ms かかる
// ため、この差は machine 認証の SHA-256 と違って観測が容易である。
//
// **遅延生成する。** パッケージ初期化で作ると、`hokora status` のような
// DB にも鍵にも触らないコマンドまで 64 MB の argon2 を 1 回払う。
// 値は誰も知らないランダムなパスワードのハッシュであり、比較は必ず失敗する。
var dummyPasswordHash = sync.OnceValues(func() (string, error) {
	salt, err := randomBytes(passwordSaltBytes)
	if err != nil {
		return "", err
	}
	secret, err := randomBytes(passwordHashBytes)
	if err != nil {
		return "", err
	}
	defer Zero(secret)

	// **argon2 は必ず semaphore を通す**(ルール 39)。一度きり(OnceValues)
	// だが、ここだけ素通しにすると「全 argon2 は semaphore 経由」の不変条件が
	// 崩れ、瞬間的に同時実行数が上限を超えうる。生成は起動後の初回ログインで
	// 遅延実行されるだけなので、待ち時間の許容のため ctx は Background。
	var hash []byte
	if err := withArgon2Slot(context.Background(), func() error {
		hash = argon2.IDKey(secret, salt, argon2Time, argon2Memory, argon2Threads, passwordHashBytes)
		return nil
	}); err != nil {
		return "", err
	}
	defer Zero(hash)

	return encodePHC(argon2Params{Memory: argon2Memory, Time: argon2Time, Threads: argon2Threads}, salt, hash), nil
})
