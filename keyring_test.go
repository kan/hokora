package main

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// gcmTagBytes は AES-GCM の認証タグ長である。暗号文はこのぶんだけ平文より長い。
const gcmTagBytes = 16

// newTestKeyring は MK を固定した keyring を作る。argon2 が 64 MB を使うため、
// keyring を作る回数は必要最小限にとどめる。
func newTestKeyring(t *testing.T, mk []byte) (*Keyring, []byte) {
	t.Helper()

	return newTestKeyringAt(t, mk, time.Unix(1700000000, 0))
}

// newTestKeyringAt は時刻を指定して keyring を作る。
func newTestKeyringAt(t *testing.T, mk []byte, now time.Time) (*Keyring, []byte) {
	t.Helper()

	kr, dek, err := NewKeyring(mk, now)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr, dek
}

func TestNewKeyring(t *testing.T) {
	t.Parallel()

	mk := testKey(t, 0x11)
	kr, dek := newTestKeyring(t, mk)

	if len(dek) != MasterKeyBytes {
		t.Errorf("dek length = %d, want %d", len(dek), MasterKeyBytes)
	}
	if bytes.Equal(dek, mk) {
		t.Error("dek equals the master key")
	}
	if bytes.Equal(dek, make([]byte, MasterKeyBytes)) {
		t.Error("dek is all zeros")
	}
	if len(kr.KDFSalt) != kdfSaltBytes {
		t.Errorf("kdf salt length = %d, want %d", len(kr.KDFSalt), kdfSaltBytes)
	}
	if len(kr.DEKNonce) != nonceBytes {
		t.Errorf("dek nonce length = %d, want %d", len(kr.DEKNonce), nonceBytes)
	}
	if kr.DEKVersion != InitialDEKVersion {
		t.Errorf("dek version = %d, want %d", kr.DEKVersion, InitialDEKVersion)
	}
	if !kr.CreatedAt.Equal(kr.UpdatedAt) {
		t.Error("created_at and updated_at differ on a new keyring")
	}

	// ラップされた DEK が平文で入っていないこと。
	if bytes.Contains(kr.DEKWrapped, dek) {
		t.Error("wrapped dek contains the plaintext dek")
	}
	if bytes.Contains(kr.DEKWrapped, mk) {
		t.Error("wrapped dek contains the master key")
	}
	// GCM の認証タグ(16 バイト)ぶんだけ長い。padding のような余計な加工が
	// 入っていないことまで見る。
	if want := MasterKeyBytes + gcmTagBytes; len(kr.DEKWrapped) != want {
		t.Errorf("wrapped dek length = %d, want %d", len(kr.DEKWrapped), want)
	}
	// salt は MK から導出されたものではなく、独立した乱数である。
	if bytes.Contains(kr.KDFSalt, mk[:kdfSaltBytes]) {
		t.Error("kdf salt appears to be derived from the master key")
	}

	wrappedBefore := bytes.Clone(kr.DEKWrapped)
	nonceBefore := bytes.Clone(kr.DEKNonce)
	saltBefore := bytes.Clone(kr.KDFSalt)

	got, err := kr.UnwrapDEK(mk)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped dek differs from the generated one")
	}

	// UnwrapDEK は MK を消さない(unseal 側が消す)。
	if !bytes.Equal(mk, testKey(t, 0x11)) {
		t.Error("UnwrapDEK modified the master key")
	}
	// keyring は unseal のたびに使い回される。UnwrapDEK が in-place で
	// 書き換えると 2 回目以降の unseal が失敗する。
	if !bytes.Equal(kr.DEKWrapped, wrappedBefore) ||
		!bytes.Equal(kr.DEKNonce, nonceBefore) ||
		!bytes.Equal(kr.KDFSalt, saltBefore) {
		t.Error("UnwrapDEK modified the keyring")
	}
	// 取り出した DEK を消しても、ラップされた側は残る(Seal() 後に再 unseal できる)。
	Zero(got)
	if !bytes.Equal(kr.DEKWrapped, wrappedBefore) {
		t.Error("the unwrapped dek shares its backing array with the wrapped blob")
	}
}

// MK の形式が不正なら keyring は作られず、生成しかけた DEK も返らない。
//
// DeriveKEK が長さで弾くため argon2 までは到達しない(このテストは安い)。
func TestNewKeyringRejectsBadMasterKey(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 16, 31, 33, 64} {
		mk := bytes.Repeat([]byte{0x01}, n)

		kr, dek, err := NewKeyring(mk, time.Unix(1700000000, 0))
		if !errors.Is(err, ErrInvalidMasterKey) {
			t.Errorf("NewKeyring with a %d-byte mk: error = %v, want ErrInvalidMasterKey", n, err)
		}
		if kr != nil {
			t.Errorf("NewKeyring with a %d-byte mk: keyring returned despite failure", n)
		}
		// 生成済みの DEK を握らせない。呼び出し側に「消す責務」だけが
		// 残るのを避けるため、失敗時は nil を返す契約になっている。
		if dek != nil {
			t.Errorf("NewKeyring with a %d-byte mk: dek returned despite failure", n)
		}
	}
}

// 時刻は UTC・秒精度に正規化される。SQLite に入る値の一貫性のため。
func TestNewKeyringNormalizesTimestamps(t *testing.T) {
	t.Parallel()

	// JST の、サブ秒を持つ時刻。
	jst := time.FixedZone("JST", 9*60*60)
	now := time.Date(2026, 7, 20, 15, 4, 5, 987654321, jst)

	kr, dek := newTestKeyringAt(t, testKey(t, 0x77), now)
	defer Zero(dek)

	if kr.CreatedAt.Location() != time.UTC {
		t.Errorf("created_at location = %v, want UTC", kr.CreatedAt.Location())
	}
	if kr.CreatedAt.Nanosecond() != 0 {
		t.Errorf("created_at has sub-second precision: %v", kr.CreatedAt)
	}
	if want := now.UTC().Truncate(time.Second); !kr.CreatedAt.Equal(want) {
		t.Errorf("created_at = %v, want %v", kr.CreatedAt, want)
	}
	if !kr.CreatedAt.Equal(kr.UpdatedAt) {
		t.Error("created_at and updated_at differ on a new keyring")
	}
	if kr.UpdatedAt.Location() != time.UTC {
		t.Errorf("updated_at location = %v, want UTC", kr.UpdatedAt.Location())
	}
}

// keyring ごとに DEK と salt が異なる(nonce の再利用と salt の使い回しがない)。
func TestNewKeyringIsUnique(t *testing.T) {
	t.Parallel()

	mk := testKey(t, 0x22)

	kr1, dek1 := newTestKeyring(t, mk)
	kr2, dek2 := newTestKeyring(t, mk)

	if bytes.Equal(dek1, dek2) {
		t.Error("two keyrings produced the same dek")
	}
	if bytes.Equal(kr1.KDFSalt, kr2.KDFSalt) {
		t.Error("two keyrings produced the same kdf salt")
	}
	if bytes.Equal(kr1.DEKNonce, kr2.DEKNonce) {
		t.Error("two keyrings produced the same nonce")
	}
	if bytes.Equal(kr1.DEKWrapped, kr2.DEKWrapped) {
		t.Error("two keyrings produced the same wrapped dek")
	}
}

// 誤った MK では unwrap が失敗する。ここが unseal 時の MK 検証そのものである
// (DESIGN §6.3)。
func TestUnwrapDEKRejectsWrongMasterKey(t *testing.T) {
	t.Parallel()

	mk := testKey(t, 0x33)
	kr, dek := newTestKeyring(t, mk)

	wrong := bytes.Clone(mk)
	wrong[MasterKeyBytes-1] ^= 0x01 // 1 ビットだけ違う MK

	got, err := kr.UnwrapDEK(wrong)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("error = %v, want ErrDecrypt", err)
	}
	if got != nil {
		t.Fatal("dek returned despite failure")
	}
	// エラーが鍵素材を漏らしていないこと(AGENTS.md ルール 20)。
	if bytes.Contains([]byte(err.Error()), dek) {
		t.Error("error message contains the dek")
	}
}

func TestUnwrapDEKRejectsTamperedKeyring(t *testing.T) {
	t.Parallel()

	mk := testKey(t, 0x44)
	kr, _ := newTestKeyring(t, mk)

	tests := []struct {
		name    string
		mutate  func(*Keyring)
		wantErr error
	}{
		{"tampered wrapped dek", func(k *Keyring) {
			k.DEKWrapped = flipByte(k.DEKWrapped, 0)
		}, ErrDecrypt},
		{"tampered auth tag", func(k *Keyring) {
			k.DEKWrapped = flipByte(k.DEKWrapped, len(k.DEKWrapped)-1)
		}, ErrDecrypt},
		{"truncated wrapped dek", func(k *Keyring) {
			k.DEKWrapped = k.DEKWrapped[:len(k.DEKWrapped)-1]
		}, ErrDecrypt},
		{"tampered nonce", func(k *Keyring) {
			k.DEKNonce = flipByte(k.DEKNonce, 0)
		}, ErrDecrypt},
		{"short nonce", func(k *Keyring) {
			k.DEKNonce = k.DEKNonce[:nonceBytes-1]
		}, ErrDecrypt},
		// salt が違えば KEK も変わるので、MK が正しくても復号できない。
		{"tampered salt", func(k *Keyring) {
			k.KDFSalt = flipByte(k.KDFSalt, 0)
		}, ErrDecrypt},
		// salt の長さが違うのはデータ破損であり、暗号の失敗とは別に扱う。
		{"short salt", func(k *Keyring) {
			k.KDFSalt = k.KDFSalt[:kdfSaltBytes-1]
		}, nil},
		{"missing salt", func(k *Keyring) {
			k.KDFSalt = nil
		}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			broken := *kr
			tt.mutate(&broken)

			dek, err := broken.UnwrapDEK(mk)
			if err == nil {
				t.Fatal("UnwrapDEK succeeded on a tampered keyring")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if dek != nil {
				t.Error("dek returned despite failure")
			}
		})
	}
}

// keyring の AAD が固定されていること。別の AAD でラップした暗号文は
// UnwrapDEK が受け付けない(バックアップ復元時の取り違え検出)。
func TestUnwrapDEKRequiresKeyringAAD(t *testing.T) {
	t.Parallel()

	mk := testKey(t, 0x55)
	kr, _ := newTestKeyring(t, mk)

	kek, err := DeriveKEK(mk, kr.KDFSalt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	defer Zero(kek)

	dek, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrapped, nonce, err := sealBytes(kek, dek, []byte("hokora/keyring/v2"))
	if err != nil {
		t.Fatalf("sealBytes: %v", err)
	}

	broken := *kr
	broken.DEKWrapped, broken.DEKNonce = wrapped, nonce

	if _, err := broken.UnwrapDEK(mk); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("error = %v, want ErrDecrypt", err)
	}
}

// keyringAAD は呼び出しごとに独立したスライスを返す。書き換えられても
// 後続の暗号操作に影響しない。
func TestKeyringAADIsNotShared(t *testing.T) {
	t.Parallel()

	first := keyringAAD()
	if string(first) != keyringAADString {
		t.Fatalf("aad = %q, want %q", first, keyringAADString)
	}
	first[0] = 'X'

	if got := string(keyringAAD()); got != keyringAADString {
		t.Fatalf("aad = %q, want %q", got, keyringAADString)
	}
}

// DEK で暗号化した secret が、keyring を経由して復号できる。M2 の全体像
// (MK → KEK → DEK → secret)が繋がっていることの確認。
func TestKeyringEndToEnd(t *testing.T) {
	t.Parallel()

	mkRaw := []byte(EncodeMasterKey(testKey(t, 0x66)) + "\n") // gen-key の出力を模す
	mk, err := DecodeMasterKey(mkRaw)
	if err != nil {
		t.Fatalf("DecodeMasterKey: %v", err)
	}

	kr, dek := newTestKeyring(t, mk)

	const (
		itemID  = int64(1)
		version = int64(1)
	)
	aad, err := itemAAD(itemID, version, kr.DEKVersion)
	if err != nil {
		t.Fatalf("itemAAD: %v", err)
	}
	plaintext := []byte("postgres://user:pass@localhost/db")
	if err := ValidateSecretValue(plaintext); err != nil {
		t.Fatalf("ValidateSecretValue: %v", err)
	}
	ciphertext, nonce, err := sealBytes(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("sealBytes: %v", err)
	}

	// ここまでの DEK を捨て、MK から取り直す(再起動 → unseal に相当)。
	Zero(dek)

	restored, err := kr.UnwrapDEK(mk)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer Zero(restored)

	got, err := openBytes(restored, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("openBytes: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip mismatch")
	}
}
