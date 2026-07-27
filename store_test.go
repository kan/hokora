package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// newTestStore は空の DB を作り、スキーマを適用して返す。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	return newTestStoreAt(t, filepath.Join(t.TempDir(), "hokora.db"))
}

func newTestStoreAt(t *testing.T, path string) *Store {
	t.Helper()

	store, err := openDatabase(t.Context(), path)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	if err := Migrate(t.Context(), store.DB()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return store
}

// insertProject / insertEnvironment は各テストが必要とする最小の行を作る。
// M2 以降のテストも同じ行を必要とするため、INSERT 文はここに集約する。
func insertProject(t *testing.T, db *sql.DB, slug string, deleted bool) int64 {
	t.Helper()

	now := time.Now().Unix()
	var deletedAt any
	if deleted {
		deletedAt = now
	}
	res, err := db.ExecContext(t.Context(),
		`INSERT INTO projects (slug, name, deleted_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		slug, slug, deletedAt, now, now,
	)
	if err != nil {
		t.Fatalf("insert project %q: %v", slug, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	return id
}

// insertEnvironment は environment を 1 行作り、その ID を返す。
// FK 違反などのエラーを見たいテストは insertEnvironmentErr を使う。
func insertEnvironment(t *testing.T, db *sql.DB, projectID int64, slug string, deleted bool) int64 {
	t.Helper()

	id, err := insertEnvironmentErr(t, db, projectID, slug, deleted)
	if err != nil {
		t.Fatalf("insert environment %q: %v", slug, err)
	}
	return id
}

func insertEnvironmentErr(t *testing.T, db *sql.DB, projectID int64, slug string, deleted bool) (int64, error) {
	t.Helper()

	now := time.Now().Unix()
	var deletedAt any
	if deleted {
		deletedAt = now
	}
	res, err := db.ExecContext(t.Context(),
		`INSERT INTO environments (project_id, slug, name, deleted_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		projectID, slug, slug, deletedAt, now, now,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DSN は "file:<path>?_pragma=..." の URI 形式なので、path 中の ? や # を
// エスケープし損ねると、SQLite がクエリ文字列の区切りとして解釈して別のファイルを
// 開いてしまう。--db に何が渡されても、開かれるのは指定されたパスであることを
// 確認する。
func TestOpenDatabaseUsesTheGivenPathVerbatim(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"plain.db", "with space.db", "q?x.db", "h#x.db", "pct%20.db",
		"amp&x.db", "eq=x.db", "plus+x.db", "日本語.db",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), name)
			store := newTestStoreAt(t, path)
			// 実際に書き込みが起きたファイルが path であることを確認する。
			insertProject(t, store.DB(), "probe", false)

			if _, err := os.Stat(path); err != nil {
				t.Fatalf("database was not created at the requested path: %v", err)
			}
		})
	}
}

// pragmaChecks は各物理接続で成立していなければならない設定である。
// foreign_keys が効いていなければ ON DELETE RESTRICT による保護が成立しない。
var pragmaChecks = []struct {
	pragma string
	want   string
}{
	{"foreign_keys", "1"},
	{"journal_mode", "wal"},
	{"busy_timeout", "5000"},
	{"synchronous", "2"}, // FULL
}

// 期待値は connectPragmas から導出せずに手で書く(導出すると、設定が消えても
// テストが一緒に消えて素通りする)。代わりに、設定した PRAGMA が全て検査対象に
// 入っていることをここで突き合わせる。
func TestEveryConfiguredPragmaIsChecked(t *testing.T) {
	t.Parallel()

	checked := make(map[string]bool, len(pragmaChecks))
	for _, c := range pragmaChecks {
		checked[c.pragma] = true
	}
	for _, p := range connectPragmas {
		name, _, ok := strings.Cut(p, "(")
		if !ok {
			t.Errorf("malformed pragma %q in connectPragmas", p)
			continue
		}
		if !checked[name] {
			t.Errorf("PRAGMA %s is configured but never verified; add it to pragmaChecks", name)
		}
	}
}

func checkPragmas(ctx context.Context, t *testing.T, conn *sql.Conn, label string) {
	t.Helper()

	for _, c := range pragmaChecks {
		var got string
		if err := conn.QueryRowContext(ctx, "PRAGMA "+c.pragma).Scan(&got); err != nil {
			t.Fatalf("%s: PRAGMA %s: %v", label, c.pragma, err)
		}
		if !strings.EqualFold(got, c.want) {
			t.Errorf("%s: PRAGMA %s = %q, want %q", label, c.pragma, got, c.want)
		}
	}
}

// 同時に開いた複数の物理接続すべてで PRAGMA が効いていることを確認する。
// 起動時に 1 接続だけで PRAGMA を実行する実装では、このテストが落ちる。
func TestPragmasAppliedToEveryConnection(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ctx := t.Context()

	// プール上限と同数を同時に取る。ここに数値を直書きすると、上限を下げたときに
	// テストは失敗せず Conn の待ちでブロックする。
	const n = maxOpenConns
	conns := make([]*sql.Conn, 0, n)
	for i := range n {
		conn, err := store.DB().Conn(ctx)
		if err != nil {
			t.Fatalf("acquire conn %d: %v", i, err)
		}
		defer conn.Close()
		conns = append(conns, conn)
	}

	// 全て同時に保持した状態で検査する(=別々の物理接続であることが保証される)。
	for _, conn := range conns {
		checkPragmas(ctx, t, conn, "conn")
	}
}

// 接続が破棄されて再生成された後も PRAGMA が効いていることを確認する。
// 接続はプールの都合や障害で作り直されるため、「起動時に 1 回適用した」では足りない。
func TestPragmasAppliedToRecreatedConnection(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ctx := t.Context()
	db := store.DB()

	// idle 接続を保持させない。Close した時点で物理接続が破棄される。
	db.SetMaxIdleConns(0)

	// SetMaxIdleConns 自体が、それまでの idle 接続(Ping が張ったもの)を閉じて
	// MaxIdleClosed を進める。基準を取っておかないと、下の検査はループが接続を
	// 作り直していなくても通ってしまう。
	before := db.Stats().MaxIdleClosed

	for i := range 3 {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("acquire conn %d: %v", i, err)
		}
		checkPragmas(ctx, t, conn, "recreated conn")
		if err := conn.Close(); err != nil {
			t.Fatalf("close conn %d: %v", i, err)
		}
	}

	if closed := db.Stats().MaxIdleClosed; closed <= before {
		t.Fatal("no connection was actually closed; the test did not exercise reconnection")
	}
}

// FK が実際に効いていること(存在しない親を参照できないこと)を確認する。
func TestForeignKeyRejectsMissingParent(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)

	_, err := insertEnvironmentErr(t, store.DB(), 9999, "prod", false)
	if err == nil {
		t.Fatal("inserted an environment referencing a nonexistent project; foreign_keys is not in effect")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ON DELETE RESTRICT が効いていること(子を持つ親を消せないこと)を確認する。
func TestForeignKeyRestrictsParentDelete(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	db := store.DB()

	projectID := insertProject(t, db, "billing", false)
	if _, err := insertEnvironmentErr(t, db, projectID, "prod", false); err != nil {
		t.Fatalf("insert environment: %v", err)
	}

	if _, err := db.ExecContext(t.Context(), `DELETE FROM projects WHERE id = ?`, projectID); err == nil {
		t.Fatal("deleted a project that still has environments; ON DELETE RESTRICT is not in effect")
	}
}

// 論理削除された slug が再利用できること(部分 UNIQUE インデックス)を確認する。
func TestDeletedSlugIsReusable(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	db := store.DB()

	insertProject(t, db, "myapp", true)  // 論理削除済み
	insertProject(t, db, "myapp", false) // 同じ slug を再利用できる

	// 生存中の slug は重複できない。
	now := time.Now().Unix()
	if _, err := db.ExecContext(t.Context(),
		`INSERT INTO projects (slug, name, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"myapp", "duplicate", now, now,
	); err == nil {
		t.Fatal("inserted a duplicate live slug; the partial unique index is not in effect")
	}
}

// 論理削除できる全てのテーブルで、UNIQUE インデックスが部分インデックスに
// なっていることを確認する。1 つでも漏れると、そのテーブルでは削除した名前を
// 二度と再利用できなくなる(THREAT_MODEL §11.2)。
func TestUniqueIndexesOnSoftDeletableTablesArePartial(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)

	// deleted_at を持つテーブル = 論理削除できるテーブル。対象を列挙せず
	// スキーマから導くことで、テーブルが増えても検査から漏れない。
	rows, err := store.DB().QueryContext(t.Context(), `
		SELECT m.name, i.name, COALESCE(i.sql, '')
		  FROM sqlite_master m
		  JOIN sqlite_master i ON i.type = 'index' AND i.tbl_name = m.name
		 WHERE m.type = 'table'
		   AND EXISTS (SELECT 1 FROM pragma_table_info(m.name) c WHERE c.name = 'deleted_at')`)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	defer rows.Close()

	checked := 0
	for rows.Next() {
		var table, index, ddl string
		if err := rows.Scan(&table, &index, &ddl); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		// ddl が空なのは UNIQUE 制約由来の自動インデックス。部分にできないので
		// そもそも使ってはならない。
		if ddl != "" && !strings.Contains(strings.ToUpper(ddl), "UNIQUE") {
			continue
		}
		checked++
		if !strings.Contains(ddl, "WHERE deleted_at IS NULL") {
			t.Errorf("%s.%s is a unique index without `WHERE deleted_at IS NULL`; "+
				"soft-deleted names would never be reusable", table, index)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	if checked == 0 {
		t.Fatal("found no unique index to check; the query is wrong")
	}
}

// 全ての外部キーが ON DELETE RESTRICT であり、audit_logs だけが FK を
// 持たないことを確認する。CASCADE を 1 箇所でも混ぜると、親の削除が子を
// 巻き込んで消してしまう(AGENTS.md ルール 57)。
func TestAllForeignKeysAreRestrict(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)

	// pragma_foreign_key_list は table-valued function としても使えるので、
	// テーブルを 1 つずつ回さずに全 FK を 1 クエリで取れる。列は名前で選ぶため、
	// SQLite のバージョンで PRAGMA の列構成が増えても壊れない。
	rows, err := store.DB().QueryContext(t.Context(), `
		SELECT m.name, f."from", f."table", f.on_delete
		  FROM sqlite_master m
		  JOIN pragma_foreign_key_list(m.name) f
		 WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("list foreign keys: %v", err)
	}
	defer rows.Close()

	found := 0
	for rows.Next() {
		var table, from, parent, onDelete string
		if err := rows.Scan(&table, &from, &parent, &onDelete); err != nil {
			t.Fatalf("scan foreign key: %v", err)
		}
		found++
		if table == "audit_logs" {
			t.Errorf("audit_logs.%s references %s; audit records must survive their referents",
				from, parent)
		}
		if got := strings.ToUpper(onDelete); got != "RESTRICT" {
			t.Errorf("%s.%s -> %s: ON DELETE %s, want RESTRICT", table, from, parent, got)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list foreign keys: %v", err)
	}
	// FK が 1 本も取れないなら、クエリが壊れていて素通りしている。
	if found == 0 {
		t.Fatal("found no foreign key to check; the query is wrong")
	}
}

// スキーマ適用直後に FK の不整合が残っていないことを確認する。
func TestForeignKeyCheckIsEmpty(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)

	rows, err := store.DB().QueryContext(t.Context(), `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()

	if rows.Next() {
		t.Error("foreign_key_check reported a violation")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign_key_check rows: %v", err)
	}
}

// ---- keyring(M3) ----

// testKeyringRow は DB 往復の確認に使うだけの keyring 行を作る。
// **argon2 を通さない**(暗号としての正しさは crypto_test.go / vault_test.go で見る)。
func testKeyringRow(version int64) *Keyring {
	at := time.Unix(1700000000, 0).UTC()
	return &Keyring{
		DEKWrapped: bytes.Repeat([]byte{0x11}, MasterKeyBytes+16),
		DEKNonce:   bytes.Repeat([]byte{0x22}, nonceBytes),
		KDFSalt:    bytes.Repeat([]byte{0x33}, kdfSaltBytes),
		DEKVersion: version,
		CreatedAt:  at,
		UpdatedAt:  at,
	}
}

func TestKeyringRoundTrip(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	want := testKeyringRow(InitialDEKVersion)
	if err := InsertKeyring(t.Context(), store.DB(), want); err != nil {
		t.Fatalf("InsertKeyring: %v", err)
	}

	got, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	switch {
	case !bytes.Equal(got.DEKWrapped, want.DEKWrapped):
		t.Errorf("dek_wrapped = %x, want %x", got.DEKWrapped, want.DEKWrapped)
	case !bytes.Equal(got.DEKNonce, want.DEKNonce):
		t.Errorf("dek_nonce = %x, want %x", got.DEKNonce, want.DEKNonce)
	case !bytes.Equal(got.KDFSalt, want.KDFSalt):
		t.Errorf("kdf_salt = %x, want %x", got.KDFSalt, want.KDFSalt)
	case got.DEKVersion != want.DEKVersion:
		t.Errorf("dek_version = %d, want %d", got.DEKVersion, want.DEKVersion)
	case !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt):
		t.Errorf("timestamps = %v / %v, want %v", got.CreatedAt, got.UpdatedAt, want.CreatedAt)
	}
}

// **keyring は上書きできない。** 2 度目の INSERT が通ると、既存の DEK を失い
// 全ての secret が復号不能になる(id = 1 固定の意図)。
func TestInsertKeyringRefusesToOverwrite(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	first := testKeyringRow(InitialDEKVersion)
	if err := InsertKeyring(t.Context(), store.DB(), first); err != nil {
		t.Fatalf("InsertKeyring: %v", err)
	}

	second := testKeyringRow(InitialDEKVersion)
	second.DEKWrapped = bytes.Repeat([]byte{0x99}, MasterKeyBytes+16)
	if err := InsertKeyring(t.Context(), store.DB(), second); err == nil {
		t.Fatal("a second InsertKeyring succeeded")
	}

	got, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if !bytes.Equal(got.DEKWrapped, first.DEKWrapped) {
		t.Error("the existing keyring was replaced")
	}
}

// rotate-master は **ラップだけ** を差し替える。dek_version と created_at を
// 動かすと、item_versions の dek_version との対応が壊れる(DESIGN §6.7)。
func TestUpdateKeyringWrapKeepsVersionAndCreatedAt(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	before := testKeyringRow(3)
	if err := InsertKeyring(t.Context(), store.DB(), before); err != nil {
		t.Fatalf("InsertKeyring: %v", err)
	}

	next := testKeyringRow(3)
	next.DEKWrapped = bytes.Repeat([]byte{0xAA}, MasterKeyBytes+16)
	next.DEKNonce = bytes.Repeat([]byte{0xBB}, nonceBytes)
	next.KDFSalt = bytes.Repeat([]byte{0xCC}, kdfSaltBytes)
	next.UpdatedAt = before.UpdatedAt.Add(time.Hour)
	if err := UpdateKeyringWrap(t.Context(), store.DB(), next); err != nil {
		t.Fatalf("UpdateKeyringWrap: %v", err)
	}

	got, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	switch {
	case !bytes.Equal(got.DEKWrapped, next.DEKWrapped) || !bytes.Equal(got.DEKNonce, next.DEKNonce):
		t.Error("the wrapped dek was not replaced")
	case !bytes.Equal(got.KDFSalt, next.KDFSalt):
		t.Error("the kdf salt was not replaced")
	case got.DEKVersion != before.DEKVersion:
		t.Errorf("dek_version = %d, want %d (unchanged)", got.DEKVersion, before.DEKVersion)
	case !got.CreatedAt.Equal(before.CreatedAt):
		t.Errorf("created_at = %v, want %v (unchanged)", got.CreatedAt, before.CreatedAt)
	case !got.UpdatedAt.Equal(next.UpdatedAt):
		t.Errorf("updated_at = %v, want %v", got.UpdatedAt, next.UpdatedAt)
	}
}

// keyring が無い DB への UPDATE は ErrKeyringMissing になる。
// 0 行更新を成功として返すと、rotate-master が「成功したのに何も変わって
// いない」状態を報告してしまう。
func TestUpdateKeyringWrapWithoutKeyring(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if err := UpdateKeyringWrap(t.Context(), store.DB(), testKeyringRow(1)); !errors.Is(err, ErrKeyringMissing) {
		t.Fatalf("error = %v, want ErrKeyringMissing", err)
	}
}

// LoadKeyring は「行が無い」を ErrKeyringMissing として区別する
// (init 前の DB を unseal しようとしたときの案内に使う)。
func TestLoadKeyringMissing(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if _, err := LoadKeyring(t.Context(), store.DB()); !errors.Is(err, ErrKeyringMissing) {
		t.Fatalf("error = %v, want ErrKeyringMissing", err)
	}
}

// ---- withTx ----

// withTx は fn が失敗したら **必ず rollback する**。
//
// 監査を本体の処理と同じトランザクションに載せる前提(THREAT_MODEL §10.4)は、
// 「失敗したら本体も残らない」ことで初めて fail closed になる。ここが漏れると
// 「監査は書けなかったが machine は作られた」行が生まれる。
func TestWithTxRollsBackOnError(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	sentinel := errors.New("boom")

	err := withTx(t.Context(), store.DB(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(),
			`INSERT INTO projects (slug, name, created_at, updated_at) VALUES ('half', 'half', 0, 0)`); err != nil {
			return err
		}
		return sentinel
	})
	// エラーは握りつぶさず、そのまま識別できる形で返る。
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the sentinel", err)
	}

	var n int
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM projects WHERE slug = 'half'`).Scan(&n); err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if n != 0 {
		t.Errorf("%d rows survived a rolled back transaction", n)
	}
}

// 成功したら commit される(rollback しかしないのでは書き込めない)。
func TestWithTxCommitsOnSuccess(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if err := withTx(t.Context(), store.DB(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(),
			`INSERT INTO projects (slug, name, created_at, updated_at) VALUES ('kept', 'kept', 0, 0)`)
		return err
	}); err != nil {
		t.Fatalf("withTx: %v", err)
	}

	var n int
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM projects WHERE slug = 'kept'`).Scan(&n); err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if n != 1 {
		t.Errorf("%d rows after a committed transaction, want 1", n)
	}
}

// トランザクションを開けない場合も、fn を呼ばずにエラーを返す。
//
// **fn が呼ばれてしまうと、tx が nil のまま本体の処理に入る。**
func TestWithTxFailsWhenTheTransactionCannotBegin(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	called := false
	err := withTx(t.Context(), store.DB(), func(*sql.Tx) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("withTx succeeded against a closed database")
	}
	if called {
		t.Error("fn was called even though the transaction could not begin")
	}
	if !strings.Contains(err.Error(), "begin transaction") {
		t.Errorf("error = %v, want it to say which step failed", err)
	}
}

// ---- Machine API のクエリ(全祖先の deleted_at 検査。ルール 58) ----

// **project と environment の両方の deleted_at を検査する。**
//
// 片方だけを見る実装(environment.deleted_at のみ)は、project を論理削除しても
// 配下の environment が生き残るため、「削除した project の secret が Machine API
// から取れる」状態を作る(THREAT_MODEL §11.1)。逆に project だけを見る実装も
// 同様に穴になるので、両方向を固定する。
func TestResolveEnvironmentChecksEveryAncestor(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	db := store.DB()

	live := insertProject(t, db, "live", false)
	insertEnvironment(t, db, live, "prod", false)
	insertEnvironment(t, db, live, "gone", true) // environment だけ論理削除

	deleted := insertProject(t, db, "archived", true)
	insertEnvironment(t, db, deleted, "prod", false) // project だけ論理削除

	// **同じ env slug が別 project に存在する。** JOIN の条件を落として
	// slug だけで引く実装だと、別 project の environment を返してしまう。
	other := insertProject(t, db, "other", false)
	otherProd := insertEnvironment(t, db, other, "prod", false)

	tests := []struct {
		name              string
		project, env      string
		wantErr           bool
		wantEnvironmentID int64
	}{
		{name: "live project and environment", project: "live", env: "prod"},
		{name: "environment soft deleted", project: "live", env: "gone", wantErr: true},
		{name: "project soft deleted", project: "archived", env: "prod", wantErr: true},
		{name: "unknown project", project: "nope", env: "prod", wantErr: true},
		{name: "unknown environment", project: "live", env: "nope", wantErr: true},
		// project をまたいだ取り違えが起きていないこと。
		{name: "same env slug under another project", project: "other", env: "prod", wantEnvironmentID: otherProd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ref, err := ResolveEnvironment(t.Context(), db, tt.project, tt.env)
			if tt.wantErr {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("error = %v, want ErrNotFound", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEnvironment: %v", err)
			}
			if ref.ProjectSlug != tt.project || ref.EnvSlug != tt.env {
				t.Errorf("ref = %+v, want %s/%s", ref, tt.project, tt.env)
			}
			if tt.wantEnvironmentID != 0 && ref.EnvironmentID != tt.wantEnvironmentID {
				t.Errorf("environment id = %d, want %d", ref.EnvironmentID, tt.wantEnvironmentID)
			}
		})
	}
}

// MachineIsActive は毎リクエスト呼ばれる(DESIGN §4.5)。
//
// **存在しない machine は「有効」ではない。** ここで true に倒れると、
// 物理削除された(あるいは取り違えた)ID のトークンが通ってしまう。
func TestMachineIsActive(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	id, _, err := CreateMachine(t.Context(), store.DB(), "app-prod", "app server",
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}

	active, err := MachineIsActive(t.Context(), store.DB(), id)
	if err != nil || !active {
		t.Fatalf("MachineIsActive = (%v, %v), want (true, nil)", active, err)
	}

	if active, err := MachineIsActive(t.Context(), store.DB(), id+1000); err != nil || active {
		t.Errorf("MachineIsActive for a missing row = (%v, %v), want (false, nil)", active, err)
	}

	if _, err := store.DB().ExecContext(t.Context(),
		`UPDATE machines SET disabled = 1 WHERE id = ?`, id); err != nil {
		t.Fatalf("disable machine: %v", err)
	}
	if active, err := MachineIsActive(t.Context(), store.DB(), id); err != nil || active {
		t.Errorf("MachineIsActive after disable = (%v, %v), want (false, nil)", active, err)
	}
}

// insertItemRow は item を 1 行入れる(暗号処理を通さない)。
//
// 一覧クエリの検査に DEK は要らない。**argon2 を払わずに済むよう、
// Vault を組み立てずに行だけを作る。**
func insertItemRow(t *testing.T, db *sql.DB, environmentID int64, key string, deleted bool) int64 {
	t.Helper()

	now := time.Now().Unix()
	var deletedAt any
	if deleted {
		deletedAt = now
	}
	res, err := db.ExecContext(t.Context(), `
		INSERT INTO items (environment_id, key, current_version, deleted_at, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?, ?)`, environmentID, key, deletedAt, now, now)
	if err != nil {
		t.Fatalf("insert item %q: %v", key, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	return id
}

// insertItemVersionRow は item_versions を 1 行入れる(値はダミー)。
func insertItemVersionRow(t *testing.T, db *sql.DB, itemID, version int64, createdBy string) {
	t.Helper()

	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO item_versions (item_id, version, value_enc, nonce, dek_version, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		itemID, version, []byte("ciphertext"), []byte("nonce"), InitialDEKVersion,
		time.Now().Unix(), createdBy); err != nil {
		t.Fatalf("insert item version: %v", err)
	}
}

// **一覧クエリは論理削除された行と、祖先が削除された行を返さない。**
//
// project を論理削除しても配下の environment / item は残る(監査ログの
// target_*_id を解決可能に保つため)。**祖先の deleted_at を検査していない
// 一覧が 1 つでもあると、削除したはずの構成が画面に出る**
// (THREAT_MODEL §11.1)。件数の集計も同じ検査を通っている必要がある。
func TestListQueriesHideDeletedRows(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	db := store.DB()

	live := insertProject(t, db, "live", false)
	dead := insertProject(t, db, "dead", true)

	liveEnv := insertEnvironment(t, db, live, "prod", false)
	deadEnv := insertEnvironment(t, db, live, "stg", true)
	orphanEnv := insertEnvironment(t, db, dead, "prod", false) // 祖先が削除済み

	insertItemRow(t, db, liveEnv, "DATABASE_URL", false)
	insertItemRow(t, db, liveEnv, "API_TOKEN", true) // 削除済み item
	insertItemRow(t, db, deadEnv, "IN_DEAD_ENV", false)
	insertItemRow(t, db, orphanEnv, "IN_DEAD_PROJECT", false)

	// ---- ListProjects ----
	projects, err := ListProjects(t.Context(), db)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 1 || projects[0].Slug != "live" {
		t.Fatalf("projects = %+v, want only live", projects)
	}
	// 件数も削除済みを数えない。
	if projects[0].Envs != 1 {
		t.Errorf("env count = %d, want 1 (the deleted environment must not be counted)", projects[0].Envs)
	}
	if projects[0].Items != 1 {
		t.Errorf("item count = %d, want 1 (deleted items and items in deleted environments must not be counted)",
			projects[0].Items)
	}

	// ---- ListEnvironments ----
	envs, err := ListEnvironments(t.Context(), db, live)
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	if len(envs) != 1 || envs[0].Slug != "prod" {
		t.Fatalf("environments = %+v, want only prod", envs)
	}
	if envs[0].Items != 1 {
		t.Errorf("item count = %d, want 1", envs[0].Items)
	}
	// 削除済み project の environment は、その project 配下としても出ない。
	if envs, err := ListEnvironments(t.Context(), db, dead); err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	} else if len(envs) != 1 {
		// **environment 自体は残る**(祖先の検査は解決側の責務。
		// ここが 0 件になると、監査対象の行が消えたと誤解される)。
		t.Errorf("environments under a deleted project = %d, want 1 (rows survive)", len(envs))
	}

	// ---- ListItems ----
	items, err := ListItems(t.Context(), db, liveEnv)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) != 1 || items[0].Key != "DATABASE_URL" {
		t.Fatalf("items = %+v, want only DATABASE_URL", items)
	}
	// **一覧の行に値は含まれない**(ルール 41 はサーバーが返さないこと)。
	// ItemRow に値のフィールドが無いこと自体が保証だが、祖先の解決を
	// 経ない呼び出しでも平文が出ないことを型で確認しておく。
	if fields := reflect.TypeOf(items[0]); fields.NumField() != 5 {
		t.Errorf("ItemRow has %d fields; make sure no value field was added", fields.NumField())
	}

	// ---- ListItemVersions ----
	itemID := items[0].ID
	insertItemVersionRow(t, db, itemID, 1, "user:1")
	versions, err := ListItemVersions(t.Context(), db, itemID)
	if err != nil {
		t.Fatalf("ListItemVersions: %v", err)
	}
	if len(versions) != 1 || !versions[0].Current || versions[0].CreatedBy != "user:1" {
		t.Errorf("versions = %+v, want one current version by user:1", versions)
	}
}

// **grant 一覧は、祖先が削除された environment を出さない。**
//
// 出してしまうと「削除済みの環境に grant がある」という実体のない表示に
// なり、剥奪すべき grant の判断を誤らせる。
func TestListMachinesHidesGrantsWithDeletedAncestors(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	db := store.DB()
	ac := auditCtx{Actor: ActorAnonymous, Now: vaultNow}

	live := insertProject(t, db, "live", false)
	dead := insertProject(t, db, "dead", true)
	liveEnv := insertEnvironment(t, db, live, "prod", false)
	deletedEnv := insertEnvironment(t, db, live, "stg", true)
	orphanEnv := insertEnvironment(t, db, dead, "prod", false)

	id, _, err := CreateMachine(t.Context(), db, "app-prod", "app server", ac)
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	for _, envID := range []int64{liveEnv, deletedEnv, orphanEnv} {
		if _, err := db.ExecContext(t.Context(),
			`INSERT INTO machine_grants (machine_id, environment_id, created_at) VALUES (?, ?, ?)`,
			id, envID, vaultNow.Unix()); err != nil {
			t.Fatalf("insert grant: %v", err)
		}
	}

	machines, err := ListMachines(t.Context(), db)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	if len(machines) != 1 {
		t.Fatalf("%d machines, want 1", len(machines))
	}
	if machines[0].LastAuthAt != nil {
		t.Error("last_auth_at is set for a machine that never authenticated")
	}
	if len(machines[0].Grants) != 1 || machines[0].Grants[0].EnvironmentID != liveEnv {
		t.Errorf("grants = %+v, want only the live environment", machines[0].Grants)
	}

	// **無効化しても行は残る**(ルール 56。machine は deleted_at を持たない)。
	if _, err := db.ExecContext(t.Context(),
		`UPDATE machines SET disabled = 1 WHERE id = ?`, id); err != nil {
		t.Fatalf("disable machine: %v", err)
	}
	machines, err = ListMachines(t.Context(), db)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	if len(machines) != 1 || !machines[0].Disabled {
		t.Errorf("machines = %+v, want one disabled machine", machines)
	}
}

// **ユーザー一覧は無効化済みも含めて返す。**
//
// user は deleted_at を持たない(監査ログの actor 参照を保つため)。
// 無効化したユーザーが一覧から消えると、**「誰が無効化されているか」を
// 画面から確認できなくなる。**
func TestListUsersIncludesDisabledUsers(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	admin := newTestUser(t, store)
	other := newTestUserNamed(t, store, "operator")

	if _, err := store.DB().ExecContext(t.Context(),
		`UPDATE users SET disabled = 1, must_change_pw = 1 WHERE id = ?`, other); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	users, err := ListUsers(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("%d users, want 2", len(users))
	}
	byID := map[int64]UserRow{}
	for _, u := range users {
		byID[u.ID] = u
		// **password_hash を持ち出さない。**
		if reflect.TypeOf(u).NumField() != 5 {
			t.Errorf("UserRow has %d fields; make sure no password field was added", reflect.TypeOf(u).NumField())
		}
	}
	if byID[admin].Disabled || byID[admin].MustChangePW {
		t.Errorf("admin = %+v, want an enabled user", byID[admin])
	}
	if !byID[other].Disabled || !byID[other].MustChangePW {
		t.Errorf("operator = %+v, want a disabled user that must change its password", byID[other])
	}
}

// **監査ログは新しい順に、上限件数まで返す。**
//
// 保持期間は無限(Q4)なので、画面は直近のみを見せる。ここで古い順に
// 返すと、上限に達した時点で **最新の記録が画面から見えなくなる。**
func TestListAuditLogsReturnsTheNewestFirst(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	for i := range 5 {
		entry := auditCtx{Actor: ActorAnonymous, Now: vaultNow.Add(time.Duration(i) * time.Minute)}.
			entry(ActionSeal, ResultSuccess, nil)
		if err := RecordAudit(t.Context(), store.DB(), entry); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}

	rows, err := ListAuditLogs(t.Context(), store.DB(), 3)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows, want 3 (the limit must be applied)", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].At.After(rows[i-1].At) {
			t.Fatalf("rows are not ordered newest first: %v", rows)
		}
	}
	if want := vaultNow.Add(4 * time.Minute).UTC(); !rows[0].At.Equal(want) {
		t.Errorf("newest row at %v, want %v", rows[0].At, want)
	}
}

// auditRowsByAction は監査行を action で引けるようにする。
//
// 同じ action が複数あるときは最新の 1 行を返す。
func auditRowsByAction(t *testing.T, db *sql.DB) map[string]AuditRow {
	t.Helper()

	rows, err := ListAuditLogs(t.Context(), db, 100)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	byAction := map[string]AuditRow{}
	for _, r := range rows {
		if _, seen := byAction[r.Action]; !seen {
			byAction[r.Action] = r
		}
	}
	return byAction
}

// **監査画面は actor と対象に名前を併記する**(#11)。
//
// 記録されるのは immutable な ID だけ(ルール 24)なので、画面がこれを解決
// しないと `user:1` が誰なのか分からない。**対象も同じ問題を持つ。**
// machine.* / user.* は target 列を持たず ID だけを記録するため、解決しないと
// 「誰が何を無効化したのか」が画面から読めない。
func TestListAuditLogsResolvesActorAndTargetNames(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	anon := secretAudit()

	projectID := insertProject(t, store.DB(), testProjectSlug, false)
	envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, false)

	machineID, _, err := CreateMachine(t.Context(), store.DB(), "app-prod", "請求バッチ", anon)
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	userID, err := CreateUser(t.Context(), store.DB(), "alice", testPassword, true, anon)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Web UI 経由の操作(actor = user)と Machine API の認証(actor = machine)。
	byUser := auditCtx{Actor: actorUser(userID), ActorUserID: &userID, Via: ViaWeb, Now: vaultNow}
	if err := CreateGrant(t.Context(), store.DB(), machineID, envID, byUser); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if err := DeleteGrant(t.Context(), store.DB(), discardLogger(), machineID, envID, byUser); err != nil {
		t.Fatalf("DeleteGrant: %v", err)
	}
	byMachine := auditCtx{Actor: actorMachine(machineID), ActorMachineID: &machineID, Now: vaultNow}
	if err := RecordAudit(t.Context(), store.DB(), byMachine.machineEntry(ActionAuthMachine, machineID)); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	var (
		user    = fmt.Sprintf("alice (user:%d)", userID)
		machine = fmt.Sprintf("請求バッチ (machine:%d)", machineID)
		path    = testProjectSlug + "/" + testEnvSlug
	)
	tests := []struct {
		action           string
		actor, target    string
		whyTargetMatters string
	}{
		{string(ActionMachineCreate), ActorAnonymous, machine,
			"target 列を持たないので、解決しないと「何を作ったか」が空欄になる"},
		{string(ActionUserCreate), ActorAnonymous, user,
			"machine と同じく target 列を持たない"},
		{string(ActionGrantCreate), user, machine + " → " + path,
			"grant は machine と environment の組で 1 つの対象である"},
		{string(ActionGrantDelete), user, machine + " → " + path,
			"grant.delete は target 列を持たず environment_id だけを記録する"},
		{string(ActionAuthMachine), machine, machine,
			"machine が actor になる唯一の経路"},
	}

	byAction := auditRowsByAction(t, store.DB())
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			row, ok := byAction[tt.action]
			if !ok {
				t.Fatalf("no %s row was recorded", tt.action)
			}
			if row.Actor != tt.actor {
				t.Errorf("actor = %q, want %q", row.Actor, tt.actor)
			}
			if row.Target != tt.target {
				t.Errorf("target = %q, want %q (%s)", row.Target, tt.target, tt.whyTargetMatters)
			}
		})
	}
}

// **名前が引けなくても行は表示できなければならない。**
//
// 名前を出すために監査行を落としたら、記録として成立しない。#7 より前に
// 作られた空名の machine と、論理削除された project / environment を見る。
// **監査は「その時点で何が起きたか」の記録なので、削除済みでも解決する**
// (ルール 58 は secret の取得経路の話であり、ここには適用しない)。
func TestListAuditLogsFallsBackWhenTheNameIsGone(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	ac := secretAudit()

	// name を検証する CreateMachine(#7)では作れない、空名の既存データ。
	res, err := store.DB().ExecContext(t.Context(), `
		INSERT INTO machines (client_id, secret_hash, name, created_at, updated_at)
		VALUES ('legacy', X'00', '', 0, 0)`)
	if err != nil {
		t.Fatalf("insert legacy machine: %v", err)
	}
	machineID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	projectID := insertProject(t, store.DB(), "gone", true)
	envID := insertEnvironment(t, store.DB(), projectID, "old", true)

	if err := RecordAudit(t.Context(), store.DB(), ac.machineEntry(ActionMachineDisable, machineID)); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}
	entry := ac.entry(ActionGrantDelete, ResultSuccess, nil)
	entry.TargetMachineID = &machineID
	entry.TargetEnvironmentID = &envID
	if err := RecordAudit(t.Context(), store.DB(), entry); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	byAction := auditRowsByAction(t, store.DB())
	ident := fmt.Sprintf("machine:%d", machineID)
	if got := byAction[string(ActionMachineDisable)].Target; got != ident {
		t.Errorf("target = %q, want the bare identifier %q", got, ident)
	}
	if want := ident + " → gone/old"; byAction[string(ActionGrantDelete)].Target != want {
		t.Errorf("target = %q, want %q (削除済みでも監査は対象を示す)",
			byAction[string(ActionGrantDelete)].Target, want)
	}
}

// **名前が引けないことより、行が消えることの方が重い。**
//
// audit_logs は FK を持たない(ルール 57)ので、参照先の行が無い ID が残るのは
// 異常ではなく正常な状態である。結合が内部結合になっていると、**その監査記録
// そのものが画面から消える。** 名前を出すために記録を失うのは本末転倒であり、
// これがこの変更で最も重い失敗モードである。
func TestListAuditLogsKeepsRowsWhoseReferencesAreMissing(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	// machines / users / environments は空のまま。どの ID も参照先を持たない。
	var (
		missingUser    = int64(9001)
		missingMachine = int64(9002)
		missingEnv     = int64(9003)
	)
	byMissingUser := auditCtx{Actor: actorUser(missingUser), ActorUserID: &missingUser, Via: ViaWeb, Now: vaultNow}
	byMissingMachine := auditCtx{Actor: actorMachine(missingMachine), ActorMachineID: &missingMachine, Now: vaultNow}

	grantDelete := byMissingUser.entry(ActionGrantDelete, ResultSuccess, nil)
	grantDelete.TargetMachineID = &missingMachine
	grantDelete.TargetEnvironmentID = &missingEnv

	entries := []AuditEntry{
		// 参照を一切持たない行(seal)も、結合の追加で落ちてはならない。
		secretAudit().entry(ActionSeal, ResultSuccess, nil),
		byMissingMachine.entry(ActionAuthMachine, ResultSuccess, nil),
		byMissingUser.userEntry(ActionUserDisable, missingUser),
		byMissingUser.machineEntry(ActionMachineDisable, missingMachine),
		grantDelete,
	}
	for _, e := range entries {
		if err := RecordAudit(t.Context(), store.DB(), e); err != nil {
			t.Fatalf("RecordAudit(%s): %v", e.Action, err)
		}
	}

	rows, err := ListAuditLogs(t.Context(), store.DB(), 100)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	// **増えるのも困る。** 結合先が複数行に増えると、1 回の操作が複数回
	// 起きたように見える。
	if len(rows) != len(entries) {
		t.Fatalf("%d rows, want %d (the join must neither drop nor multiply audit rows)", len(rows), len(entries))
	}

	user := fmt.Sprintf("user:%d", missingUser)
	machine := fmt.Sprintf("machine:%d", missingMachine)
	want := map[string]struct{ actor, target string }{
		string(ActionSeal):           {ActorAnonymous, ""},
		string(ActionAuthMachine):    {machine, ""},
		string(ActionUserDisable):    {user, user},
		string(ActionMachineDisable): {user, machine},
		// environment が引けないとき、'/' だけの path を作らない。
		string(ActionGrantDelete): {user, machine},
	}
	for _, row := range rows {
		w, ok := want[row.Action]
		if !ok {
			t.Errorf("unexpected action %q", row.Action)
			continue
		}
		if row.Actor != w.actor {
			t.Errorf("%s: actor = %q, want the bare identifier %q", row.Action, row.Actor, w.actor)
		}
		if row.Target != w.target {
			t.Errorf("%s: target = %q, want %q", row.Action, row.Target, w.target)
		}
	}
}

// **上限は「監査行の件数」に効く。並びは同じ時刻でも決まる。**
//
// at は秒精度なので、続けて起きた操作は同じ時刻になる。時刻だけで並べると
// 同秒の行の順序が不定になり、**上限で切ったときに直近の操作が落ちうる。**
// 結合を足した後も、LIMIT が結合後の行数ではなく監査行に効いていることを見る。
func TestListAuditLogsBreaksTiesByIDUnderTheLimit(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	anon := secretAudit()
	machineID, _, err := CreateMachine(t.Context(), store.DB(), "app-prod", "web01", anon)
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}

	// CreateMachine の machine.create を含め、全て同じ時刻の行になる。
	actions := []Action{
		ActionMachineRotateSecret, ActionGrantCreate, ActionGrantDelete,
		ActionMachineDisable, ActionAuthMachine,
	}
	for _, action := range actions {
		if err := RecordAudit(t.Context(), store.DB(), anon.machineEntry(action, machineID)); err != nil {
			t.Fatalf("RecordAudit(%s): %v", action, err)
		}
	}

	const limit = 3
	rows, err := ListAuditLogs(t.Context(), store.DB(), limit)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(rows) != limit {
		t.Fatalf("%d rows, want %d", len(rows), limit)
	}
	target := fmt.Sprintf("web01 (machine:%d)", machineID)
	for i, row := range rows {
		if want := string(actions[len(actions)-1-i]); row.Action != want {
			t.Errorf("rows[%d].Action = %q, want %q (the newest of the same second must come first)",
				i, row.Action, want)
		}
		// 上限で切っても名前の解決は効いている。
		if row.Target != target {
			t.Errorf("rows[%d].Target = %q, want %q", i, row.Target, target)
		}
	}
}

// **列と構造体フィールドの対応を、行そのもので固定する。**
//
// この画面のクエリは SELECT の列順と Scan の引数順が一致していることだけを
// 頼りにしている。名前解決のために列を足したり並べ替えたりすると、**取り違え
// ても型が合ってしまう**(action / result / remote_addr / detail は全て文字列)。
// 送信元や結果が別の列の値になった監査ログは、記録が無いより質が悪い。
func TestListAuditLogsMapsEveryColumnToItsField(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	detail := &AuditDetail{
		Reason:        ptr(ReasonInvalidCredentials),
		Via:           ptr(ViaWeb),
		SubjectDigest: ptr(subjectDigest("ghost")),
	}
	ac := auditCtx{Actor: ActorAnonymous, Via: ViaWeb, RemoteAddr: ptr("10.8.0.9"), Now: vaultNow}
	if err := RecordAudit(t.Context(), store.DB(), ac.entry(ActionAuthUser, ResultFailure, detail)); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}
	// entry() は detail を値でコピーするので、渡した構造体をそのまま
	// marshal したものが行に入っている。
	wantDetail, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}

	rows, err := ListAuditLogs(t.Context(), store.DB(), 10)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1", len(rows))
	}
	row := rows[0]
	if !row.At.Equal(vaultNow) {
		t.Errorf("At = %v, want %v", row.At, vaultNow.UTC())
	}
	for _, f := range []struct{ field, got, want string }{
		{"Actor", row.Actor, ActorAnonymous},
		{"Action", row.Action, string(ActionAuthUser)},
		{"Target", row.Target, ""},
		{"Result", row.Result, string(ResultFailure)},
		{"RemoteAddr", row.RemoteAddr, "10.8.0.9"},
		{"Detail", row.Detail, string(wantDetail)},
	} {
		if f.got != f.want {
			t.Errorf("%s = %q, want %q", f.field, f.got, f.want)
		}
	}
}

// **名前は記録側に入れない。表示のときに現在の値を引く**(ルール 24)。
//
// 記録時の名前を行に持たせると、改名の前後で同じ主体の行が別物に見え、
// 追跡が切れる。行には ID しか入っていないこと、そして改名すると**過去の行の
// 表示も追随する**ことの両方を見る。片方だけだと、記録側に名前を書き込む
// 実装に変えても気付けない。
func TestAuditRowsRecordIdentifiersNotNames(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	anon := secretAudit()
	projectID := insertProject(t, store.DB(), testProjectSlug, false)
	envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, false)

	const machineName = "shukka-batch"
	const username = "operator"
	machineID, _, err := CreateMachine(t.Context(), store.DB(), "app-prod", machineName, anon)
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	userID, err := CreateUser(t.Context(), store.DB(), username, testPassword, true, anon)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	byUser := auditCtx{Actor: actorUser(userID), ActorUserID: &userID, Via: ViaWeb, Now: vaultNow}
	if err := CreateGrant(t.Context(), store.DB(), machineID, envID, byUser); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	raw, err := store.DB().QueryContext(t.Context(),
		`SELECT actor, COALESCE(target, '') FROM audit_logs`)
	if err != nil {
		t.Fatalf("select audit_logs: %v", err)
	}
	defer func() {
		if err := raw.Close(); err != nil {
			t.Errorf("close rows: %v", err)
		}
	}()

	idents := map[string]struct{}{
		ActorAnonymous: {}, actorUser(userID): {}, actorMachine(machineID): {},
	}
	for raw.Next() {
		var actor, target string
		if err := raw.Scan(&actor, &target); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if _, ok := idents[actor]; !ok {
			t.Errorf("actor column = %q; the row must hold an immutable identifier only", actor)
		}
		for _, name := range []string{machineName, username} {
			if strings.Contains(actor+" "+target, name) {
				t.Errorf("the row (%q / %q) contains the name %q; renaming would rewrite history",
					actor, target, name)
			}
		}
	}
	if err := raw.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	// 改名しても行は変わらないので、表示だけが現在の名前に追随する。
	if _, err := store.DB().ExecContext(t.Context(),
		`UPDATE machines SET name = 'renamed' WHERE id = ?`, machineID); err != nil {
		t.Fatalf("rename machine: %v", err)
	}
	byAction := auditRowsByAction(t, store.DB())
	if want := fmt.Sprintf("renamed (machine:%d)", machineID); byAction[string(ActionMachineCreate)].Target != want {
		t.Errorf("target = %q, want %q (the name is resolved at display time)",
			byAction[string(ActionMachineCreate)].Target, want)
	}
}

// **識別子は必ず残す。**
//
// machines.name に UNIQUE 制約は無く、名前は後から変えられる。名前だけの表示に
// すると、同名の machine を区別できず、監査の追跡が名前の一意性という
// **成り立っていない前提**に乗る(ルール 24)。
func TestAuditSubjectAlwaysShowsTheIdentifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ident, disp string
		want        string
	}{
		{"名前が引ければ併記する", "user:1", "alice", "alice (user:1)"},
		{"名前が無ければ識別子だけを出す", "machine:3", "", "machine:3"},
		{"名前が識別子を騙っても識別子は落とさない", "machine:3", "machine:9", "machine:9 (machine:3)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := auditSubject(tt.ident, tt.disp); got != tt.want {
				t.Errorf("auditSubject(%q, %q) = %q, want %q", tt.ident, tt.disp, got, tt.want)
			}
		})
	}
}

// **対象の表示は、DB 経由では作れない組み合わせも含めて閉じている必要がある。**
//
// どの列が埋まるかは action ごとに違い、実装は action を見ずに列の有無だけで
// 組み立てる。実際に起きる組み合わせだけを DB 経由で確かめると、**まだ無い
// action を足したときに初めて壊れる。**
func TestAuditTargetPrefersTheRecordedTargetColumn(t *testing.T) {
	t.Parallel()

	id := func(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

	tests := []struct {
		name string
		refs auditTargetRefs
		want string
		why  string
	}{
		{
			name: "対象を持たない",
			refs: auditTargetRefs{},
			want: "",
			why:  "seal / logout は対象を持たない。何かを組み立てると嘘になる",
		},
		{
			name: "machine だけ",
			refs: auditTargetRefs{MachineID: id(3), MachineName: "web01"},
			want: "web01 (machine:3)",
			why:  "machine.* は target 列を持たず、解決しないと空欄になる",
		},
		{
			name: "user だけ",
			refs: auditTargetRefs{UserID: id(1), UserName: "alice"},
			want: "alice (user:1)",
			why:  "user.* も同じく target 列を持たない",
		},
		{
			name: "machine と user が両方立つ",
			refs: auditTargetRefs{MachineID: id(3), UserID: id(1)},
			want: "machine:3 → user:1",
			why:  "順序が固定でないと、同じ形の行が読み手ごとに別の意味に見える",
		},
		{
			name: "target 列だけ",
			refs: auditTargetRefs{Stored: "DATABASE_URL"},
			want: "DATABASE_URL",
			why:  "item の key は ID から引き直せない",
		},
		{
			name: "machine と target 列",
			refs: auditTargetRefs{MachineID: id(3), MachineName: "web01", Stored: "myapp/prod"},
			want: "web01 (machine:3) → myapp/prod",
			why:  "grant.create は machine と environment の組で 1 つの対象である",
		},
		{
			name: "target 列と environment の両方が引ける",
			refs: auditTargetRefs{Stored: "myapp/prod", ProjectSlug: "myapp", EnvSlug: "staging"},
			want: "myapp/prod",
			why:  "記録時点の文字列を優先する。現在の値で上書きすると、その時どう見えていたかが失われる",
		},
		{
			name: "environment だけ引ける",
			refs: auditTargetRefs{ProjectSlug: "myapp", EnvSlug: "prod"},
			want: "myapp/prod",
			why:  "grant.delete は target 列を持たず environment_id だけを記録する",
		},
		{
			name: "environment は引けたが project が引けない",
			refs: auditTargetRefs{MachineID: id(3), EnvSlug: "prod"},
			want: "machine:3",
			why:  "半端に解決した '/prod' は、別 project の environment と読み違える",
		},
		{
			name: "project は引けたが environment が引けない",
			refs: auditTargetRefs{ProjectSlug: "myapp"},
			want: "",
			why:  "'myapp/' は environment を指していない",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := auditTarget(tt.refs); got != tt.want {
				t.Errorf("auditTarget = %q, want %q (%s)", got, tt.want, tt.why)
			}
		})
	}
}

// **一覧クエリ自身が祖先の deleted_at を検査する**(AGENTS.md ルール 58)。
//
// 呼び出し側が先に ResolveEnvironment / FindItem を通していることに依存すると、
// その手順を踏まない呼び出しが増えた時点で、削除済み project 配下の item が
// 一覧に出る。**クエリ側で閉じる。**
func TestListQueriesCheckAncestorsThemselves(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	projectID := insertProject(t, store.DB(), "myapp", false)
	envID := insertEnvironment(t, store.DB(), projectID, "prod", false)

	res, err := store.DB().ExecContext(t.Context(), `
		INSERT INTO items (environment_id, key, current_version, created_at, updated_at)
		VALUES (?, 'DATABASE_URL', 1, 0, 0)`, envID)
	if err != nil {
		t.Fatalf("insert item: %v", err)
	}
	itemID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `
		INSERT INTO item_versions (item_id, version, value_enc, nonce, dek_version, created_at, created_by)
		VALUES (?, 1, X'00', X'00', 1, 0, 'test')`, itemID); err != nil {
		t.Fatalf("insert item version: %v", err)
	}

	// 削除前は見える。
	items, err := ListItems(t.Context(), store.DB(), envID)
	if err != nil || len(items) != 1 {
		t.Fatalf("ListItems = %d rows, %v", len(items), err)
	}
	versions, err := ListItemVersions(t.Context(), store.DB(), itemID)
	if err != nil || len(versions) != 1 {
		t.Fatalf("ListItemVersions = %d rows, %v", len(versions), err)
	}

	tests := []struct {
		name string
		sql  string
	}{
		{"project deleted", `UPDATE projects SET deleted_at = 1 WHERE id = ?`},
		{"environment deleted", `UPDATE environments SET deleted_at = 1 WHERE id = ?`},
	}
	ids := map[string]int64{"project deleted": projectID, "environment deleted": envID}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 同じ DB を使うので並列にしない。各ケースの後に元へ戻す。
			if _, err := store.DB().ExecContext(t.Context(), tt.sql, ids[tt.name]); err != nil {
				t.Fatalf("soft delete: %v", err)
			}
			defer func() {
				restore := strings.Replace(tt.sql, "deleted_at = 1", "deleted_at = NULL", 1)
				if _, err := store.DB().ExecContext(t.Context(), restore, ids[tt.name]); err != nil {
					t.Fatalf("restore: %v", err)
				}
			}()

			if items, err := ListItems(t.Context(), store.DB(), envID); err != nil || len(items) != 0 {
				t.Errorf("ListItems returned %d rows under a deleted ancestor (%v)", len(items), err)
			}
			if versions, err := ListItemVersions(t.Context(), store.DB(), itemID); err != nil || len(versions) != 0 {
				t.Errorf("ListItemVersions returned %d rows under a deleted ancestor (%v)", len(versions), err)
			}
		})
	}
}
