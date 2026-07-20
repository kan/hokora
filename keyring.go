package main

import (
	"fmt"
	"time"
)

// InitialDEKVersion は最初の DEK に与えるバージョンである。
// DEK のローテーション(DESIGN §6.8)で増える。
const InitialDEKVersion = 1

// NewKeyring は DEK を生成し、MK から導出した KEK でラップした keyring を返す
// (DESIGN §6.3)。
//
// 返り値の dek は unsealed 状態の Vault が保持するものであり、呼び出し側が
// 責任を持って Zero する。MK は呼び出し側が保持したままである(この関数は
// 消さない)。KEK はこの関数の中で使い切り、必ず消す。
//
// now を引数で受けるのは、テストから時刻を固定できるようにするためである。
func NewKeyring(mk []byte, now time.Time) (kr *Keyring, dek []byte, err error) {
	salt, err := randomBytes(kdfSaltBytes)
	if err != nil {
		return nil, nil, err
	}

	dek, err = GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	// 以降で失敗したら DEK は誰にも渡らないので、その場で消す。
	defer func() {
		if err != nil {
			Zero(dek)
			dek = nil
		}
	}()

	wrapped, nonce, err := wrapDEK(mk, salt, dek)
	if err != nil {
		return nil, nil, err
	}

	at := now.UTC().Truncate(time.Second)
	return &Keyring{
		DEKWrapped: wrapped,
		DEKNonce:   nonce,
		KDFSalt:    salt,
		DEKVersion: InitialDEKVersion,
		CreatedAt:  at,
		UpdatedAt:  at,
	}, dek, nil
}

// UnwrapDEK は MK から KEK を導出し、keyring の DEK を取り出す。
//
// **MK の検証はここで行われる**(DESIGN §6.3)。誤った MK から導出した KEK では
// GCM の認証タグ検証が失敗するので、ErrDecrypt が返る。KEK は使い切って消す。
//
// 返り値の DEK は呼び出し側が Zero する。
func (k *Keyring) UnwrapDEK(mk []byte) ([]byte, error) {
	kek, err := DeriveKEK(mk, k.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("derive kek: %w", err)
	}
	defer Zero(kek)

	dek, err := openBytes(kek, k.DEKNonce, k.DEKWrapped, keyringAAD())
	if err != nil {
		return nil, err
	}
	if len(dek) != MasterKeyBytes {
		// ラップされていたのが DEK でない。DB の取り違えや復元ミスを疑う。
		Zero(dek)
		return nil, ErrDecrypt
	}
	return dek, nil
}

// wrapDEK は MK と salt から KEK を導出し、DEK をラップする。KEK は消す。
func wrapDEK(mk, salt, dek []byte) (wrapped, nonce []byte, err error) {
	kek, err := DeriveKEK(mk, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("derive kek: %w", err)
	}
	defer Zero(kek)

	wrapped, nonce, err = sealBytes(kek, dek, keyringAAD())
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}
	return wrapped, nonce, nil
}
