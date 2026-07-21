package main

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// newSecretFixture は unsealed な Vault と、project / environment を返す。
//
// **argon2 は keyring 作成と unseal の 2 回。** 以降のサブテストは同じ
// fixture を使い回す(t.Parallel を付けないのは、同じ DB を順に触るため)。
func newSecretFixture(t *testing.T) (*Vault, *Store, *EnvironmentRef) {
	t.Helper()

	v, store, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	projectID := insertProject(t, store.DB(), testProjectSlug, false)
	envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, false)
	return v, store, &EnvironmentRef{
		ProjectSlug: testProjectSlug, EnvSlug: testEnvSlug,
		ProjectID: projectID, EnvironmentID: envID,
	}
}

func secretAudit() auditCtx {
	return auditCtx{Actor: ActorAnonymous, Via: ViaSocket, Now: vaultNow}
}

// **item_versions は追記のみ**(AGENTS.md ルール 55)。
//
// 更新で過去の版を書き換えてしまうと、履歴からの復元ができなくなるうえ、
// 監査ログの version が指す中身が後から変わる。**「更新できてしまう」
// 実装は、通常のラウンドトリップのテストでは検出できない**ので、過去版の
// 暗号文そのものが不変であることを見る。
func TestPutSecretAppendsVersions(t *testing.T) {
	t.Parallel()

	v, store, env := newSecretFixture(t)
	ac := secretAudit()

	const (
		first  = "value-one"
		second = "value-two"
		third  = "value-three"
	)
	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte(first), ac); err != nil {
		t.Fatalf("PutSecret v1: %v", err)
	}
	firstEnc, firstNonce := readVersionBytes(t, store, 1)

	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte(second), ac); err != nil {
		t.Fatalf("PutSecret v2: %v", err)
	}
	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte(third), ac); err != nil {
		t.Fatalf("PutSecret v3: %v", err)
	}

	item, err := FindItem(t.Context(), store.DB(), env.EnvironmentID, "DATABASE_URL")
	if err != nil {
		t.Fatalf("FindItem: %v", err)
	}
	if item.CurrentVersion != 3 {
		t.Errorf("current version = %d, want 3", item.CurrentVersion)
	}

	// **item 行は 1 つのまま、版が 3 つ積まれる。**
	if got := countRows(t, store, `SELECT COUNT(*) FROM items`); got != 1 {
		t.Errorf("%d item rows, want 1", got)
	}
	if got := countRows(t, store, `SELECT COUNT(*) FROM item_versions`); got != 3 {
		t.Errorf("%d item_versions rows, want 3", got)
	}

	// **1 版目の暗号文と nonce は書き換わっていない。**
	gotEnc, gotNonce := readVersionBytes(t, store, 1)
	if !bytes.Equal(gotEnc, firstEnc) || !bytes.Equal(gotNonce, firstNonce) {
		t.Error("version 1 was rewritten by a later write")
	}
	// nonce は版ごとに異なる(同じ DEK で再利用しない)。
	secondEnc, secondNonce := readVersionBytes(t, store, 2)
	if bytes.Equal(firstNonce, secondNonce) {
		t.Error("the nonce was reused across versions")
	}
	if bytes.Equal(firstEnc, secondEnc) {
		t.Error("two different values produced the same ciphertext")
	}

	// version 0 は現行版、それ以外は指定版。
	for _, tt := range []struct {
		version int64
		want    string
	}{{0, third}, {1, first}, {2, second}, {3, third}} {
		got, err := RevealSecret(t.Context(), v, env, "DATABASE_URL", tt.version, ac)
		if err != nil {
			t.Fatalf("RevealSecret version %d: %v", tt.version, err)
		}
		if got != tt.want {
			t.Errorf("RevealSecret version %d = %q, want %q", tt.version, got, tt.want)
		}
	}

	// 存在しない版は ErrNotFound(暗号処理まで進まない)。
	if _, err := RevealSecret(t.Context(), v, env, "DATABASE_URL", 99, ac); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevealSecret of a missing version = %v, want ErrNotFound", err)
	}
	if _, err := RevealSecret(t.Context(), v, env, "NO_SUCH_KEY", 0, ac); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevealSecret of a missing key = %v, want ErrNotFound", err)
	}

	// 書き込みと表示は全て監査されている(ルール 22)。
	if got := countAuditLogs(t, store.DB(), ActionSecretWrite); got != 3 {
		t.Errorf("%d write audit rows, want 3", got)
	}
	if got := countAuditLogs(t, store.DB(), ActionSecretReveal); got != 4 {
		t.Errorf("%d reveal audit rows, want 4", got)
	}
}

// **値の検証はサーバー側で行う**(DESIGN §5.3)。
//
// 不正な値で行が残ると、後から復号できるのに JSON に出せない secret が
// できる。**弾いたときに 1 行も書かないこと**まで見る。
func TestPutSecretValidatesTheValue(t *testing.T) {
	t.Parallel()

	v, store, env := newSecretFixture(t)
	ac := secretAudit()

	tests := []struct {
		name  string
		key   string
		value []byte
		want  error
	}{
		{"too large", "BIG", bytes.Repeat([]byte("a"), MaxSecretValueBytes+1), errSecretValueTooLarge},
		{"invalid utf-8", "BROKEN", []byte{0xff, 0xfe}, errSecretValueNotUTF8},
		{"nul byte", "NUL", []byte("a\x00b"), errSecretValueHasNUL},
		{"invalid key", "lowercase", []byte("value"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PutSecret(t.Context(), v, env, tt.key, tt.value, ac)
			if err == nil {
				t.Fatal("PutSecret succeeded, want an error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
			// **エラーに値そのものを含めない**(ルール 20)。
			if strings.Contains(err.Error(), string(tt.value)) && len(tt.value) > 0 {
				t.Errorf("the error message contains the value: %v", err)
			}
		})
	}

	// 上限ちょうどは通る(境界)。
	if err := PutSecret(t.Context(), v, env, "MAX",
		bytes.Repeat([]byte("a"), MaxSecretValueBytes), ac); err != nil {
		t.Errorf("PutSecret at the size limit: %v", err)
	}
	// 空の値も通る(空文字を持つ環境変数は正当)。
	if err := PutSecret(t.Context(), v, env, "EMPTY", nil, ac); err != nil {
		t.Errorf("PutSecret with an empty value: %v", err)
	}
	if got := countRows(t, store, `SELECT COUNT(*) FROM items`); got != 2 {
		t.Errorf("%d item rows, want 2 (rejected values must not create rows)", got)
	}
}

// **論理削除した key は再利用できる**(部分 UNIQUE インデックス)。
//
// 再利用時に古い item 行へ版を積んでしまうと、削除済みの item が復活する。
// 新しい行になり、版が 1 から始まることを見る。
func TestPutSecretReusesADeletedKey(t *testing.T) {
	t.Parallel()

	v, store, env := newSecretFixture(t)
	ac := secretAudit()

	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte("old"), ac); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte("old2"), ac); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	old, err := FindItem(t.Context(), store.DB(), env.EnvironmentID, "DATABASE_URL")
	if err != nil {
		t.Fatalf("FindItem: %v", err)
	}

	if err := DeleteItem(t.Context(), store.DB(), env, "DATABASE_URL", ac); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	// **物理削除しない**(ルール 56)。監査ログの item_id を解決可能に保つ。
	if got := countRows(t, store, `SELECT COUNT(*) FROM item_versions WHERE item_id = `+itoa(old.ID)); got != 2 {
		t.Error("the versions of the deleted item were removed")
	}
	if _, err := FindItem(t.Context(), store.DB(), env.EnvironmentID, "DATABASE_URL"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindItem after delete = %v, want ErrNotFound", err)
	}
	if _, err := RevealSecret(t.Context(), v, env, "DATABASE_URL", 1, ac); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevealSecret after delete = %v, want ErrNotFound", err)
	}
	// 二重削除は失敗する(冪等にしない。監査に 2 件目が残ると誤解を生む)。
	if err := DeleteItem(t.Context(), store.DB(), env, "DATABASE_URL", ac); err == nil {
		t.Error("deleting twice succeeded")
	}

	// 同じ key で作り直す。
	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte("new"), ac); err != nil {
		t.Fatalf("PutSecret after delete: %v", err)
	}
	fresh, err := FindItem(t.Context(), store.DB(), env.EnvironmentID, "DATABASE_URL")
	if err != nil {
		t.Fatalf("FindItem: %v", err)
	}
	if fresh.ID == old.ID {
		t.Fatal("the deleted item row was revived")
	}
	if fresh.CurrentVersion != 1 {
		t.Errorf("current version = %d, want 1 for a new item", fresh.CurrentVersion)
	}
	got, err := RevealSecret(t.Context(), v, env, "DATABASE_URL", 0, ac)
	if err != nil {
		t.Fatalf("RevealSecret: %v", err)
	}
	if got != "new" {
		t.Errorf("value = %q, want %q", got, "new")
	}
}

// **監査を記録できなければ、secret の操作は確定しない**(THREAT_MODEL §10.4)。
//
// fail closed の本質は「本体の更新ごと巻き戻る」ことである。
// 「エラーを返すが行は残る」実装は、戻り値だけ見るテストでは通ってしまう。
func TestSecretOperationsFailClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	v, store, env := newSecretFixture(t)
	ac := secretAudit()

	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte(testSecretValue), ac); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	breakAuditTable(t, store)

	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte("second"), ac); err == nil {
		t.Error("PutSecret succeeded while the audit log was broken")
	}
	if got := countRows(t, store, `SELECT COUNT(*) FROM item_versions`); got != 1 {
		t.Errorf("%d item_versions rows, want 1 (the write must roll back)", got)
	}
	if got := countRows(t, store,
		`SELECT current_version FROM items WHERE key = 'DATABASE_URL'`); got != 1 {
		t.Errorf("current_version = %d, want 1", got)
	}

	// **平文を返さない。**
	value, err := RevealSecret(t.Context(), v, env, "DATABASE_URL", 0, ac)
	if err == nil {
		t.Error("RevealSecret succeeded while the audit log was broken")
	}
	if value != "" {
		t.Error("RevealSecret returned a plaintext even though the audit record failed")
	}

	if err := DeleteItem(t.Context(), store.DB(), env, "DATABASE_URL", ac); err == nil {
		t.Error("DeleteItem succeeded while the audit log was broken")
	}
	if got := countRows(t, store,
		`SELECT COUNT(*) FROM items WHERE deleted_at IS NOT NULL`); got != 0 {
		t.Error("the item was marked deleted even though the audit record failed")
	}

	// project / environment の作成も fail closed(ルール 26 の「各種 create」)。
	if _, err := CreateProject(t.Context(), store.DB(), "another", "", ac); err == nil {
		t.Error("CreateProject succeeded while the audit log was broken")
	}
	if got := countRows(t, store, `SELECT COUNT(*) FROM projects WHERE slug = 'another'`); got != 0 {
		t.Error("the project row was left behind")
	}
	if _, err := CreateEnvironment(t.Context(), store.DB(), testProjectSlug, "stg", "", ac); err == nil {
		t.Error("CreateEnvironment succeeded while the audit log was broken")
	}
	if got := countRows(t, store, `SELECT COUNT(*) FROM environments WHERE slug = 'stg'`); got != 0 {
		t.Error("the environment row was left behind")
	}
}

// **grant の削除は fail open**(緊急遮断操作。ルール 27)。
//
// 監査が壊れていても権限剥奪は通す。ここが fail closed だと、監査 DB の
// 障害中に侵害された machine の grant を外せなくなる。
func TestDeleteGrantIsFailOpen(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ac := secretAudit()

	projectID := insertProject(t, store.DB(), testProjectSlug, false)
	envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, false)
	machineID, _, err := CreateMachine(t.Context(), store.DB(), "app-prod", "app", ac)
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	if err := CreateGrant(t.Context(), store.DB(), machineID, envID, ac); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	breakAuditTable(t, store)

	if err := DeleteGrant(t.Context(), store.DB(), discardLogger(), machineID, envID, ac); err != nil {
		t.Fatalf("DeleteGrant while the audit log is broken: %v", err)
	}
	granted, err := HasGrant(t.Context(), store.DB(), machineID, envID)
	if err != nil {
		t.Fatalf("HasGrant: %v", err)
	}
	if granted {
		t.Error("the grant survived a fail open delete")
	}
	// 存在しない grant の削除は失敗する(消えていないのに成功を返さない)。
	if err := DeleteGrant(t.Context(), store.DB(), discardLogger(), machineID, envID, ac); err == nil {
		t.Error("deleting a missing grant succeeded")
	}
}

// ---- 補助 ----

// readVersionBytes は指定した版の暗号文と nonce を読む。
func readVersionBytes(t *testing.T, store *Store, version int64) (valueEnc, nonce []byte) {
	t.Helper()

	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT value_enc, nonce FROM item_versions WHERE version = ?`, version).
		Scan(&valueEnc, &nonce); err != nil {
		t.Fatalf("select item version %d: %v", version, err)
	}
	return valueEnc, nonce
}

// countRows は 1 つの整数を返すクエリを実行する。
func countRows(t *testing.T, store *Store, query string) int64 {
	t.Helper()

	var n sql.NullInt64
	if err := store.DB().QueryRowContext(t.Context(), query).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n.Int64
}
