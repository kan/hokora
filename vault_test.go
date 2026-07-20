package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var vaultNow = time.Unix(1700000000, 0)

// newSealedVault は **keyring を作らずに** sealed な Vault を返す。
//
// argon2 は 64 MB / time=3 で回る。keyring の作成だけで 1 回走るので、
// unseal しないテスト(sealed 状態の挙動、mux の疎通、レート制限など)では
// keyring を作らない。unseal を試みれば ErrKeyringMissing になるが、
// これらのテストはそこに触れない。
func newSealedVault(t *testing.T) *Vault {
	t.Helper()

	store := newTestStore(t)
	return NewVault(store.DB(), discardLogger(), 16)
}

// newTestVault は keyring を作成済みの DB と、sealed な Vault を返す。
//
// **argon2 は 64 MB / time=3 で回る。** keyring の作成で 1 回、unseal のたびに
// もう 1 回走るので、テストごとの unseal 回数は必要最小限にとどめる。
// keyring が要らないテストは newSealedVault を使うこと。
func newTestVault(t *testing.T) (v *Vault, store *Store, mk []byte) {
	t.Helper()

	store = newTestStore(t)
	mk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	kr, dek, err := NewKeyring(mk, vaultNow)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	Zero(dek)
	if err := InsertKeyring(t.Context(), store.DB(), kr); err != nil {
		t.Fatalf("InsertKeyring: %v", err)
	}

	return NewVault(store.DB(), discardLogger(), 16), store, mk
}

// unsealForTest は unseal し、失敗したらテストを止める。
func unsealForTest(t *testing.T, v *Vault, mk []byte) {
	t.Helper()

	if err := v.Unseal(t.Context(), mk, socketAudit(vaultNow)); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
}

func TestVaultStartsSealed(t *testing.T) {
	t.Parallel()

	v := newSealedVault(t)

	status := v.Status()
	if status.State != StateSealed {
		t.Errorf("state = %v, want sealed", status.State)
	}
	if status.DEKVersion != 0 {
		t.Errorf("dek version = %d, want 0 while sealed", status.DEKVersion)
	}
	// sealed では暗号操作ができない。
	if err := v.WithDEK(func([]byte, int64) error { return nil }); !errors.Is(err, ErrSealed) {
		t.Errorf("WithDEK error = %v, want ErrSealed", err)
	}
	// sealed ではトークンも発行できない(C6 の入口の確認)。
	_, _, err := v.IssueToken(vaultNow, func() (int64, error) {
		t.Error("verify must not run while sealed")
		return 0, nil
	})
	if !errors.Is(err, ErrSealed) {
		t.Errorf("IssueToken error = %v, want ErrSealed", err)
	}
}

func TestVaultUnsealAndSeal(t *testing.T) {
	t.Parallel()

	v, store, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	if got := v.Status(); got.State != StateUnsealed || got.DEKVersion != InitialDEKVersion {
		t.Fatalf("status = %+v, want unsealed with dek version %d", got, InitialDEKVersion)
	}

	// DEK が使えること、そして seal 後にその同じバッファがゼロクリアされること。
	var dekCopy, dekAlias []byte
	if err := v.WithDEK(func(dek []byte, version int64) error {
		if len(dek) != MasterKeyBytes {
			t.Errorf("dek length = %d, want %d", len(dek), MasterKeyBytes)
		}
		if version != InitialDEKVersion {
			t.Errorf("dek version = %d, want %d", version, InitialDEKVersion)
		}
		dekCopy = bytes.Clone(dek)
		dekAlias = dek
		return nil
	}); err != nil {
		t.Fatalf("WithDEK: %v", err)
	}
	if bytes.Equal(dekCopy, make([]byte, MasterKeyBytes)) {
		t.Fatal("dek is all zeros while unsealed")
	}

	// unseal の監査が記録されていること(fail closed の対象)。
	if n := countAuditLogs(t, store.DB(), ActionUnsealAttempt); n != 1 {
		t.Errorf("%d unseal audit rows, want 1", n)
	}
	// **経路が残ること。** via が落ちると、socket 経由の unseal と M5 の
	// Web UI 経由の unseal を後から区別できない。
	assertAuditVia(t, store, ActionUnsealAttempt, ViaSocket)

	v.Seal(t.Context(), socketAudit(vaultNow))

	if got := v.Status(); got.State != StateSealed || got.DEKVersion != 0 {
		t.Fatalf("status = %+v, want sealed", got)
	}
	if err := v.WithDEK(func([]byte, int64) error { return nil }); !errors.Is(err, ErrSealed) {
		t.Errorf("WithDEK after seal = %v, want ErrSealed", err)
	}
	// **DEK が実際にゼロクリアされていること。** 参照を落としただけでは、
	// メモリ上に鍵が残る(DESIGN §6.6)。
	if !bytes.Equal(dekAlias, make([]byte, MasterKeyBytes)) {
		t.Error("the dek buffer was not zeroed by Seal")
	}
	if n := countAuditLogs(t, store.DB(), ActionSeal); n != 1 {
		t.Errorf("%d seal audit rows, want 1", n)
	}
	assertAuditVia(t, store, ActionSeal, ViaSocket)
}

// assertAuditVia は当該 action の監査行に via が入っていることを確かめる。
func assertAuditVia(t *testing.T, store *Store, action Action, want string) {
	t.Helper()

	var detail string
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT detail FROM audit_logs WHERE action = ?`, string(action)).Scan(&detail); err != nil {
		t.Fatalf("select %s audit row: %v", action, err)
	}
	if !strings.Contains(detail, `"via":"`+want+`"`) {
		t.Errorf("%s detail = %q, want via = %q", action, detail, want)
	}
}

// **unseal 後にメモリ上へ MK / KEK を残さない**(AGENTS.md ルール 14、
// ROADMAP M3 の完了条件)。保持してよいのは DEK だけである。
func TestVaultUnsealKeepsOnlyTheDEK(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)
	mkCopy := bytes.Clone(mk)
	unsealForTest(t, v, mk)

	// 呼び出し側のバッファを消しても DEK は生きている = MK を握っていない。
	// 握っていれば、ここで vault の中身も壊れる。
	Zero(mk)
	if err := v.WithDEK(func(dek []byte, _ int64) error {
		if len(dek) != MasterKeyBytes {
			t.Errorf("dek length = %d, want %d", len(dek), MasterKeyBytes)
		}
		if bytes.Equal(dek, make([]byte, MasterKeyBytes)) {
			t.Error("the dek was zeroed together with the caller's master key buffer")
		}
		// DEK は MK そのものではない(ラップされた別の鍵である)。
		if bytes.Equal(dek, mkCopy) {
			t.Error("the vault holds the master key as if it were the dek")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithDEK: %v", err)
	}

	// **鍵素材を持てるフィールドは dek だけである。** MK / KEK を保持する
	// フィールドが後から足されたら、ここで気付く。
	var keyFields []string
	vt := reflect.TypeOf(v).Elem()
	for i := range vt.NumField() {
		if f := vt.Field(i); f.Type == reflect.TypeOf([]byte(nil)) {
			keyFields = append(keyFields, f.Name)
		}
	}
	if len(keyFields) != 1 || keyFields[0] != "dek" {
		t.Errorf("Vault has byte-slice fields %v, want only [dek]", keyFields)
	}
}

// Status は observability 用であって、鍵素材の出口ではない。
func TestVaultStatusDoesNotExposeKeyMaterial(t *testing.T) {
	t.Parallel()

	st := reflect.TypeOf(VaultStatus{})
	for i := range st.NumField() {
		if f := st.Field(i); f.Type == reflect.TypeOf([]byte(nil)) {
			t.Errorf("VaultStatus exposes a byte slice field %q", f.Name)
		}
	}
}

// 誤った MK では unseal できず、状態も変わらない。
func TestVaultUnsealWrongMasterKey(t *testing.T) {
	t.Parallel()

	v, store, mk := newTestVault(t)
	wrong := flipByte(mk, 0)

	err := v.Unseal(t.Context(), wrong, socketAudit(vaultNow))
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("error = %v, want ErrDecrypt", err)
	}
	if got := v.Status(); got.State != StateSealed {
		t.Fatalf("state = %v after a failed unseal, want sealed", got.State)
	}

	// 失敗も監査対象である(DESIGN §10.1)。理由は allowlist の定数で入る。
	var result, detail string
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT result, detail FROM audit_logs WHERE action = ?`, string(ActionUnsealAttempt),
	).Scan(&result, &detail); err != nil {
		t.Fatalf("select unseal audit row: %v", err)
	}
	if result != string(ResultFailure) {
		t.Errorf("result = %q, want failure", result)
	}
	if !bytes.Contains([]byte(detail), []byte(ReasonInvalidMasterKey)) {
		t.Errorf("detail = %q, want it to contain %q", detail, ReasonInvalidMasterKey)
	}
	// 正しい MK なら通る(状態が壊れていないことの確認)。
	unsealForTest(t, v, mk)
}

func TestVaultUnsealTwice(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	if err := v.Unseal(t.Context(), mk, socketAudit(vaultNow)); !errors.Is(err, ErrAlreadyUnsealed) {
		t.Fatalf("error = %v, want ErrAlreadyUnsealed", err)
	}
	if got := v.Status(); got.State != StateUnsealed {
		t.Errorf("state = %v, want unsealed", got.State)
	}
}

// keyring が無い DB(init 前)では unseal できない。
func TestVaultUnsealWithoutKeyring(t *testing.T) {
	t.Parallel()

	v := newSealedVault(t)

	mk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := v.Unseal(t.Context(), mk, socketAudit(vaultNow)); !errors.Is(err, ErrKeyringMissing) {
		t.Fatalf("error = %v, want ErrKeyringMissing", err)
	}
	if got := v.Status(); got.State != StateSealed {
		t.Errorf("state = %v, want sealed", got.State)
	}
}

// seal は idempotent である。sealed に対して呼んでも壊れない。
func TestVaultSealIsIdempotent(t *testing.T) {
	t.Parallel()

	v := newSealedVault(t)
	v.Seal(t.Context(), socketAudit(vaultNow))
	v.Seal(t.Context(), socketAudit(vaultNow))

	if got := v.Status(); got.State != StateSealed {
		t.Errorf("state = %v, want sealed", got.State)
	}
}

// ---- 監査の fail closed / fail open(THREAT_MODEL §10.4) ----

// **unseal は fail closed。** 監査ログを書けないなら unseal しない。
func TestVaultUnsealFailsClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	v, store, mk := newTestVault(t)
	breakAuditTable(t, store)

	err := v.Unseal(t.Context(), mk, socketAudit(vaultNow))
	if err == nil {
		t.Fatal("Unseal succeeded even though the audit log could not be written")
	}
	if got := v.Status(); got.State != StateUnsealed {
		// 期待どおり: 監査が書けないので sealed のまま。
		if got.State != StateSealed {
			t.Fatalf("state = %v, want sealed", got.State)
		}
	} else {
		t.Fatal("the vault was unsealed without an audit record")
	}
	// 復号そのものには成功しているので、MK の誤りとは区別できる形で失敗する。
	if errors.Is(err, ErrDecrypt) {
		t.Errorf("error = %v, want an audit failure rather than ErrDecrypt", err)
	}
}

// **seal は fail open。** 監査 DB が壊れていても遮断できなければならない。
func TestVaultSealSucceedsWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	v, store, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	// unseal 後に監査テーブルを壊す。これが「監査 DB の障害」である。
	breakAuditTable(t, store)

	v.Seal(t.Context(), socketAudit(vaultNow))

	if got := v.Status(); got.State != StateSealed {
		t.Fatal("Seal did not seal the vault when the audit log was unavailable")
	}
	if err := v.WithDEK(func([]byte, int64) error { return nil }); !errors.Is(err, ErrSealed) {
		t.Errorf("WithDEK after seal = %v, want ErrSealed", err)
	}
}

// **master.rotate は fail closed。** 緊急操作ではないので監査を要求する。
func TestVaultRotateMasterFailsClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	v, store, oldMK := newTestVault(t)
	newMK, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	breakAuditTable(t, store)

	if err := v.RotateMaster(t.Context(), oldMK, newMK, socketAudit(vaultNow)); err == nil {
		t.Fatal("RotateMaster succeeded even though the audit log could not be written")
	}

	// 旧 MK が引き続き有効であること(トランザクションが巻き戻っている)。
	kr, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	dek, err := kr.UnwrapDEK(oldMK)
	if err != nil {
		t.Fatalf("the old master key no longer works after a failed rotate: %v", err)
	}
	Zero(dek)
}

// ---- rotate-master(DESIGN §6.7) ----

func TestVaultRotateMaster(t *testing.T) {
	t.Parallel()

	v, store, oldMK := newTestVault(t)
	newMK, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	before, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	wantDEK, err := before.UnwrapDEK(oldMK)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	defer Zero(wantDEK)

	if err := v.RotateMaster(t.Context(), oldMK, newMK, socketAudit(vaultNow)); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}

	after, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}

	// 新 MK で開けること。**DEK は変わらない**(secret の再暗号化は不要)。
	gotDEK, err := after.UnwrapDEK(newMK)
	if err != nil {
		t.Fatalf("the new master key does not open the keyring: %v", err)
	}
	defer Zero(gotDEK)
	if !bytes.Equal(gotDEK, wantDEK) {
		t.Error("the dek changed during a master key rotation")
	}
	if after.DEKVersion != before.DEKVersion {
		t.Errorf("dek version changed from %d to %d", before.DEKVersion, after.DEKVersion)
	}

	// 旧 MK では開けないこと。
	if _, err := after.UnwrapDEK(oldMK); !errors.Is(err, ErrDecrypt) {
		t.Errorf("the old master key still opens the keyring: %v", err)
	}
	// ラップも salt も引き直されていること(同じ nonce / salt を使い回さない)。
	if bytes.Equal(after.KDFSalt, before.KDFSalt) {
		t.Error("the kdf salt was reused across a rotation")
	}
	if bytes.Equal(after.DEKNonce, before.DEKNonce) {
		t.Error("the dek nonce was reused across a rotation")
	}

	if n := countAuditLogs(t, store.DB(), ActionMasterRotate); n != 1 {
		t.Errorf("%d master.rotate audit rows, want 1", n)
	}
	assertAuditVia(t, store, ActionMasterRotate, ViaSocket)
}

// 現行 MK が誤っていたら中止し、**旧 MK が引き続き有効である**。
func TestVaultRotateMasterWrongCurrentKey(t *testing.T) {
	t.Parallel()

	v, store, oldMK := newTestVault(t)
	newMK, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if err := v.RotateMaster(t.Context(), flipByte(oldMK, 0), newMK, socketAudit(vaultNow)); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("error = %v, want ErrDecrypt", err)
	}

	kr, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	dek, err := kr.UnwrapDEK(oldMK)
	if err != nil {
		t.Fatalf("the old master key stopped working after a failed rotate: %v", err)
	}
	Zero(dek)

	if n := countAuditLogs(t, store.DB(), ActionMasterRotate); n != 0 {
		t.Errorf("%d master.rotate audit rows after a failure, want 0", n)
	}
}

// rotate-master は unsealed 状態の DEK に影響しない(DEK が変わらないため)。
func TestVaultRotateMasterKeepsUnsealedState(t *testing.T) {
	t.Parallel()

	v, _, oldMK := newTestVault(t)
	unsealForTest(t, v, oldMK)

	newMK, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := v.RotateMaster(t.Context(), oldMK, newMK, socketAudit(vaultNow)); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}

	if got := v.Status(); got.State != StateUnsealed {
		t.Errorf("state = %v after rotate, want unsealed", got.State)
	}
	if err := v.WithDEK(func(dek []byte, _ int64) error {
		if bytes.Equal(dek, make([]byte, MasterKeyBytes)) {
			t.Error("the in-memory dek was zeroed by a rotation")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithDEK after rotate: %v", err)
	}
}
