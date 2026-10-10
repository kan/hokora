package main

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// newV1Store は schema v1 で止めた DB を作る(v2 への移行を試すための土台)。
func newV1Store(t *testing.T) *Store {
	t.Helper()

	store, err := openDatabase(t.Context(), filepath.Join(t.TempDir(), "hokora.db"))
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	if err := migrate(t.Context(), store.DB(), migrations[:1]); err != nil {
		t.Fatalf("migrate to v1: %v", err)
	}
	return store
}

// **migrations の並びが、migrations/ のファイルと一致する。**
//
// 移行は「ファイルを足す」「go:embed の変数を足す」「migrations に並べる」の
// 3 箇所を手で揃える。ファイルを足して並べ忘れても、順序を取り違えても、
// ビルドは通り schemaVersion もそれらしい値になる。ファイル名の番号順に
// 並べたものと突き合わせる。
func TestMigrationsMatchTheFiles(t *testing.T) {
	t.Parallel()

	dir := os.DirFS("migrations")
	files, err := fs.Glob(dir, "*.sql")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	slices.Sort(files)

	// migrations[0] は schema.sql(v1)。ファイルは 0002 から始まる。
	if len(files) != len(migrations)-1 {
		t.Fatalf("migrations/ has %d files but migrations lists %d steps after schema.sql", len(files), len(migrations)-1)
	}
	for i, path := range files {
		version := i + 2
		if want := fmt.Sprintf("%04d_", version); !strings.HasPrefix(path, want) {
			t.Errorf("migrations/%s: want a file named %s*.sql for schema version %d (numbers must be contiguous)", path, want, version)
		}
		content, err := fs.ReadFile(dir, path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(content) != migrations[version-1] {
			t.Errorf("migrations[%d] is not the content of %s", version-1, path)
		}
	}
}

// 同時に走った 2 つの移行は、どちらも成功する。後発は「列が既にある」で失敗
// するが、DB は先発が正しく移行済みである。
func TestMigrateConcurrently(t *testing.T) {
	t.Parallel()

	store := newV1Store(t)

	const runs = 4
	errs := make(chan error, runs)
	var wg sync.WaitGroup
	for range runs {
		wg.Go(func() { errs <- Migrate(t.Context(), store.DB()) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	}
	assertUserVersion(t, store.DB(), schemaVersion)
}

// **--migrate-only は DB を新しく作らない。** パスを打ち間違えた更新作業が、
// 空の DB と新しい MK を作って「成功」しないようにする。
func TestCmdInitMigrateOnly(t *testing.T) {
	t.Parallel()

	t.Run("fails without creating anything when the file is missing", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "typo", "hokora.db")
		if err := cmdInit(t.Context(), []string{"-db", path, "-migrate-only"}); err == nil {
			t.Fatal("cmdInit --migrate-only succeeded although the database does not exist")
		}
		if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("--migrate-only left something behind at %s (stat err = %v)", filepath.Dir(path), err)
		}
	})

	t.Run("migrates an existing database", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "hokora.db")
		if err := cmdInit(t.Context(), []string{"-db", path}); err != nil {
			t.Fatalf("cmdInit: %v", err)
		}
		// v1 に戻した状態を作る代わりに、初期化済みの DB への再実行が通ることを
		// 確かめる(移行そのものは TestMigrateV1ToV2... が見る)。
		if err := cmdInit(t.Context(), []string{"-db", path, "-migrate-only"}); err != nil {
			t.Fatalf("cmdInit --migrate-only on an existing database: %v", err)
		}
	})
}

// auditBatchRow は監査行の id と batch_id である。
type auditBatchRow struct {
	ID    int64
	Batch sql.NullInt64
}

// auditBatchRows は監査行の (id, batch_id) を id 順に返す。
// action が空でなければ、その action の行だけを返す。
func auditBatchRows(t *testing.T, db *sql.DB, action Action) []auditBatchRow {
	t.Helper()

	rows, err := db.QueryContext(t.Context(),
		`SELECT id, batch_id FROM audit_logs WHERE ? = '' OR action = ? ORDER BY id`,
		string(action), string(action))
	if err != nil {
		t.Fatalf("list audit rows: %v", err)
	}
	defer rows.Close()

	var out []auditBatchRow
	for rows.Next() {
		var r auditBatchRow
		if err := rows.Scan(&r.ID, &r.Batch); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// splitBatches は行を「batch_id を持たない行」と「先頭行の id ごとの後続行」に分ける。
func splitBatches(rows []auditBatchRow) (noBatch []int64, members map[int64][]int64) {
	members = map[int64][]int64{}
	for _, r := range rows {
		if r.Batch.Valid {
			members[r.Batch.Int64] = append(members[r.Batch.Int64], r.ID)
		} else {
			noBatch = append(noBatch, r.ID)
		}
	}
	return noBatch, members
}

// **v1 の DB を v2 に上げても、既存の監査行には触れない。**
//
// 監査ログは追記専用である(THREAT_MODEL §10.7)。v1 の bulk fetch の行を
// 「同じ秒だから同じ呼び出し」と推測してまとめることはしない。
func TestMigrateV1ToV2LeavesExistingAuditRowsUntouched(t *testing.T) {
	t.Parallel()

	store := newV1Store(t)
	db := store.DB()

	// v1 の bulk fetch 1 回分(同じ秒・machine・environment・送信元の 3 行)。
	for range 3 {
		if _, err := db.ExecContext(t.Context(), `
			INSERT INTO audit_logs (at, actor, actor_machine_id, action, target_environment_id, result, remote_addr)
			VALUES (1000, 'machine:1', 1, 'secret.read', 10, 'success', '10.0.0.2')`); err != nil {
			t.Fatalf("insert v1 audit row: %v", err)
		}
	}
	const snapshot = `SELECT group_concat(id || '|' || at || '|' || actor || '|' || action || '|' || result, ';') FROM audit_logs`
	before := queryStrings(t, db, snapshot)

	if err := Migrate(t.Context(), db); err != nil {
		t.Fatalf("Migrate v1 -> v2: %v", err)
	}
	assertUserVersion(t, db, schemaVersion)

	if after := queryStrings(t, db, snapshot); !slices.Equal(before, after) {
		t.Errorf("audit rows changed during the migration:\nbefore: %v\nafter:  %v", before, after)
	}
	noBatch, members := splitBatches(auditBatchRows(t, db, ""))
	if len(noBatch) != 3 || len(members) != 0 {
		t.Errorf("after migration: %d rows without a batch and batches %v, want 3 untouched rows and no batch", len(noBatch), members)
	}
}

// schemaShape は DB の全テーブルの列と、全てのインデックス・トリガ・ビューを、
// 名前順の一覧で返す。
func schemaShape(t *testing.T, db *sql.DB) []string {
	t.Helper()

	columns := queryStrings(t, db, `
		SELECT 'column ' || m.name || '.' || c.name || ' ' || c.type || ' notnull=' || c."notnull" || ' pk=' || c.pk
		FROM sqlite_master m, pragma_table_info(m.name) c
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'
		ORDER BY m.name, c.name`)
	others := queryStrings(t, db, `
		SELECT type || ' ' || name || ' ' || COALESCE(sql, '') FROM sqlite_master
		WHERE type <> 'table' AND name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	return append(columns, others...)
}

// queryStrings は 1 列の問い合わせ結果を文字列の一覧で返す。
func queryStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), query)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// **新規の DB と、v1 から上げた DB で、スキーマ全体の形が一致する。**
//
// 経路を 1 本にした(migrations を先頭から踏む)ことを、結果の側から固定する。
// 「新規では通るのに、移行した本番 DB では列やインデックスが無い」を防ぐ。
func TestMigrateFreshAndUpgradedSchemasMatch(t *testing.T) {
	t.Parallel()

	fresh := schemaShape(t, newTestStore(t).DB())

	upgradedStore := newV1Store(t)
	if err := Migrate(t.Context(), upgradedStore.DB()); err != nil {
		t.Fatalf("Migrate v1 -> v2: %v", err)
	}
	upgraded := schemaShape(t, upgradedStore.DB())

	if !slices.Equal(fresh, upgraded) {
		t.Errorf("the schema differs between a fresh and an upgraded database:\nfresh:    %v\nupgraded: %v", fresh, upgraded)
	}

	// 「設定した」ではなく「在る」を確かめる。
	for _, want := range []string{"column audit_logs.batch_id INTEGER", "index idx_audit_batch ", "index idx_audit_head ", "index idx_audit_head_machine ", "index idx_audit_head_env "} {
		if !slices.ContainsFunc(fresh, func(s string) bool { return strings.HasPrefix(s, want) }) {
			t.Errorf("audit_logs is missing %q; got %v", want, fresh)
		}
	}
}

// 移行に失敗したら、user_version も列も元のままである(中途半端な DB を残さない)。
func TestMigrateRollsBackWhenAStepFails(t *testing.T) {
	t.Parallel()

	store := newV1Store(t)

	// 2 つ目(本物の v2)は通り、3 つ目で失敗する。**先に通った v2 も巻き戻る。**
	steps := []string{migrations[0], migrations[1], `CREATE TABLE zz_new (id INTEGER); THIS IS NOT SQL;`}
	if err := migrate(t.Context(), store.DB(), steps); err == nil {
		t.Fatal("migrate succeeded although a step is broken")
	}
	assertUserVersion(t, store.DB(), 1)

	if n := countRows(t, store, `SELECT COUNT(*) FROM pragma_table_info('audit_logs') WHERE name = 'batch_id'`); n != 0 {
		t.Error("batch_id exists after a failed migration; the earlier step was not rolled back")
	}
}

func batchEntries(n int, at time.Time) []AuditEntry {
	ac := machineAudit(1, "10.0.0.2", at)
	entries := make([]AuditEntry, 0, n)
	for i := range n {
		target := fmt.Sprintf("myapp/prod/KEY_%d", i)
		entry := ac.entry(ActionSecretRead, ResultSuccess, nil)
		entry.Target = &target
		entries = append(entries, entry)
	}
	return entries
}

func recordBatch(t *testing.T, db *sql.DB, entries []AuditEntry) error {
	t.Helper()
	return withTx(t.Context(), db, func(tx *sql.Tx) error {
		return RecordAuditBatch(t.Context(), tx, entries)
	})
}

// **batch の先頭行は batch_id を持たず、残りは先頭行の id を持つ。**
// 一覧は batch_id の無い行だけを拾い、後続の行は先頭行の id で引く。
func TestRecordAuditBatch(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name string
		// before は batch より前に書いておく単独の行の数である。
		before int
		n      int
	}{
		{"first rows of an empty table", 0, 3},
		{"after existing rows", 5, 4},
		{"two entries", 2, 2},
		// 1 件だけの呼び出し(単一取得)は、先頭行しか無いので単独の行と同じになる。
		{"a single entry is not a batch", 2, 1},
		{"no entries write nothing", 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db := newTestStore(t).DB()
			for _, e := range batchEntries(tt.before, now) {
				if err := RecordAudit(t.Context(), db, e); err != nil {
					t.Fatalf("RecordAudit: %v", err)
				}
			}
			if err := recordBatch(t, db, batchEntries(tt.n, now)); err != nil {
				t.Fatalf("RecordAuditBatch: %v", err)
			}

			noBatch, members := splitBatches(auditBatchRows(t, db, ""))
			// 単独の行と、batch の先頭行(あれば 1 行)。
			if want := tt.before + min(tt.n, 1); len(noBatch) != want {
				t.Errorf("rows without a batch = %d, want %d", len(noBatch), want)
			}
			if tt.n < 2 {
				if len(members) != 0 {
					t.Errorf("batches = %v, want none", members)
				}
				return
			}
			head := int64(tt.before + 1)
			if got := members[head]; len(members) != 1 || len(got) != tt.n-1 {
				t.Errorf("batches = %v, want %d rows pointing at the head row %d", members, tt.n-1, head)
			}
		})
	}
}

// 検証に落ちる行が混ざっていたら、batch 全体が書かれない(fail closed)。
func TestRecordAuditBatchRollsBackOnAnInvalidEntry(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	entries := batchEntries(3, time.Unix(1_700_000_000, 0))
	entries[2].Action = "not.in.the.allowlist"

	if err := recordBatch(t, db, entries); err == nil {
		t.Fatal("RecordAuditBatch accepted an action outside the allowlist")
	}
	if rows := auditBatchRows(t, db, ""); len(rows) != 0 {
		t.Errorf("audit rows after a failed batch = %v, want none", rows)
	}
}

// **並行する bulk fetch が、互いの batch を混ぜない。**
//
// 後続の行は「同じトランザクションで直前に書いた先頭行の id」を持つ。別の
// 呼び出しの先頭行を指してしまうと、画面で他人の読み取りに混ざって見える。
// race detector では見えないので、結果で確かめる(ルール 68)。
func TestRecordAuditBatchUnderConcurrency(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	now := time.Unix(1_700_000_000, 0)

	const (
		workers = 8
		rounds  = 15
		size    = 5
	)
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds*2)
	for range workers {
		wg.Go(func() {
			for range rounds {
				// batch と単独の行を混ぜて、id の並びを揺らす。
				errs <- recordBatch(t, db, batchEntries(size, now))
				errs <- RecordAudit(t.Context(), db, batchEntries(1, now)[0])
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent audit write: %v", err)
		}
	}

	noBatch, members := splitBatches(auditBatchRows(t, db, ""))
	// 単独の行と、各 batch の先頭行。
	if want := workers * rounds * 2; len(noBatch) != want {
		t.Errorf("rows without a batch = %d, want %d", len(noBatch), want)
	}
	if len(members) != workers*rounds {
		t.Errorf("batches = %d, want %d", len(members), workers*rounds)
	}
	for head, ids := range members {
		if !slices.Contains(noBatch, head) {
			t.Errorf("batch %d: the head row is missing or belongs to another batch", head)
		}
		// 同じトランザクションの行は先頭行に続く連番になる(他の書き込みが
		// 割り込んでいない = 自分の先頭行を指している)。
		for i, id := range ids {
			if len(ids) != size-1 || id != head+int64(i)+1 {
				t.Errorf("batch %d = %v, want %d consecutive ids after the head", head, ids, size-1)
				break
			}
		}
	}
}

// **Machine API の bulk fetch は、key ごとの行を 1 つの batch として記録する。**
// 部品(RecordAuditBatch)が正しくても、API がそれを呼んでいなければ意味がない
// ので、外から叩いて確かめる。
func TestAPIBulkSecretReadIsRecordedAsOneBatch(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusOK {
		t.Fatalf("bulk fetch: status = %d, want 200 (body %q)", w.Code, w.Body.String())
	}

	rows := auditBatchRows(t, f.store.DB(), ActionSecretRead)
	// **行は key の数だけある**(ルール 23)。まとめるのは表示だけである。
	if len(rows) < 2 {
		t.Fatalf("secret.read rows = %d, want one per key (at least 2)", len(rows))
	}
	if rows[0].Batch.Valid {
		t.Errorf("head row %d: batch_id = %v, want NULL", rows[0].ID, rows[0].Batch)
	}
	want := sql.NullInt64{Int64: rows[0].ID, Valid: true}
	for _, r := range rows[1:] {
		if r.Batch != want {
			t.Errorf("row %d: batch_id = %v, want the id of the head row (%d)", r.ID, r.Batch, rows[0].ID)
		}
	}
}

// 単一取得(/v1/secrets/{key})は 1 行だけなので batch にならない。
func TestAPISingleSecretReadIsNotABatch(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if w := f.do(t, http.MethodGet, "/v1/secrets/DATABASE_URL?project=myapp&env=prod", token, nil); w.Code != http.StatusOK {
		t.Fatalf("single fetch: status = %d, want 200", w.Code)
	}

	rows := auditBatchRows(t, f.store.DB(), ActionSecretRead)
	if len(rows) != 1 || rows[0].Batch.Valid {
		t.Errorf("secret.read rows = %v, want one row without a batch", rows)
	}
}

// **バイナリより新しい DB は移行せず、中身にも触れない。**
//
// 既存の TestMigrateRejectsUnknownSchema はエラーが返ることだけを見ている。
// ここでは「拒否した後に user_version もスキーマも元のまま」まで確かめる。
// 拒否の前に何かを書いてしまうと、新しいバイナリが作った DB を古いバイナリが
// 壊すことになる。
func TestMigrateLeavesANewerDatabaseUntouched(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// steps は「このバイナリが知っている移行」である。
		steps []string
		// bump が真なら、DB の user_version を現行より 1 つ先に進めておく。
		bump bool
		want int
	}{
		// v2 の DB を、v1 までしか知らないバイナリで開いた状況(更新の巻き戻し)。
		{name: "v1 binary on a v2 database", steps: migrations[:1], want: schemaVersion},
		{name: "current binary on a future database", steps: migrations[:], bump: true, want: schemaVersion + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newTestStore(t)
			db := store.DB()
			if tt.bump {
				if _, err := db.ExecContext(t.Context(), fmt.Sprintf("PRAGMA user_version = %d", tt.want)); err != nil {
					t.Fatalf("bump user_version: %v", err)
				}
			}
			before := schemaShape(t, db)

			if err := migrate(t.Context(), db, tt.steps); err == nil {
				t.Fatal("migrate accepted a database newer than the steps it knows")
			}

			assertUserVersion(t, db, tt.want)
			if after := schemaShape(t, db); !slices.Equal(before, after) {
				t.Errorf("the schema changed although the migration was refused:\nbefore: %v\nafter:  %v", before, after)
			}
		})
	}
}

// 空の DB からの移行が途中で失敗したら、v1 のテーブルも残らない。
//
// TestMigrateRollsBackWhenAStepFails は v1 からの失敗を見ている。新規の DB では
// schema.sql(v1)が同じトランザクションで先に通るので、そちらも巻き戻ることを
// 確かめる(テーブルだけ在って user_version が 0 の DB は、次の init が
// 「テーブルが既にある」で通れなくなる)。
func TestMigrateFromEmptyRollsBackEverything(t *testing.T) {
	t.Parallel()

	store, err := openDatabase(t.Context(), filepath.Join(t.TempDir(), "hokora.db"))
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	steps := []string{migrations[0], `ALTER TABLE no_such_table ADD COLUMN x INTEGER;`}
	if err := migrate(t.Context(), store.DB(), steps); err == nil {
		t.Fatal("migrate succeeded although a step is broken")
	}
	assertUserVersion(t, store.DB(), 0)
	if shape := schemaShape(t, store.DB()); len(shape) != 0 {
		t.Errorf("a failed migration from an empty database left objects behind: %v", shape)
	}

	// 失敗の後でも、正しい手順でやり直せる。
	if err := Migrate(t.Context(), store.DB()); err != nil {
		t.Fatalf("Migrate after a failed attempt: %v", err)
	}
	assertUserVersion(t, store.DB(), schemaVersion)
}

// **v1 のままの DB は OpenStore が拒否する。**
//
// v2 のバイナリは全ての監査 INSERT に batch_id を含める。v1 の DB を開けて
// しまうと、起動はするのに監査が全て失敗し、fail closed の操作(secret の
// 読み取り、認証)が全滅する。更新後に `hokora init` を忘れた場合は、起動の
// 時点で止める。既存の TestOpenStoreRejectsMismatchedSchema は「未初期化」と
// 「新しすぎる」だけを見ていた。
func TestOpenStoreRejectsAnOlderSchema(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	store, err := openDatabase(t.Context(), path)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if err := migrate(t.Context(), store.DB(), migrations[:1]); err != nil {
		t.Fatalf("migrate to v1: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if opened, err := OpenStore(t.Context(), path); err == nil {
		opened.Close()
		t.Error("OpenStore opened a v1 database")
	}
	if opened, err := OpenStoreReadOnly(t.Context(), path); err == nil {
		opened.Close()
		t.Error("OpenStoreReadOnly opened a v1 database")
	}
}

// keyringAndUsers は keyring と users の全行を文字列の一覧で返す。
func keyringAndUsers(t *testing.T, db *sql.DB) []string {
	t.Helper()

	keyring := queryStrings(t, db, `
		SELECT 'keyring ' || id || ' ' || hex(kdf_salt) || ' ' || hex(dek_wrapped) || ' ' || hex(dek_nonce) || ' ' || dek_version
		FROM keyring ORDER BY id`)
	users := queryStrings(t, db, `SELECT 'user ' || id || ' ' || username || ' ' || password_hash FROM users ORDER BY id`)
	return append(keyring, users...)
}

// **--migrate-only は、運用中の v1 の DB ファイルを v2 に上げる。keyring と
// admin は作り直さない。**
//
// 既存のテストは「初期化済み(v2)の DB への再実行が通る」ことしか見ていない。
// 更新作業で実際に踏むのは、keyring・admin・監査行を持つ v1 のファイルである。
// keyring を作り直せば新しい MK が出力され、既存の secret は復号できなくなる。
func TestCmdInitMigrateOnlyUpgradesAV1DatabaseFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	if err := cmdInit(t.Context(), []string{"-db", path}); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	// init 済みのファイルを v1 に戻す(v2 が足したものだけを外す)。
	// keyring と admin は init が作った本物の行のまま残る。
	store, err := openDatabase(t.Context(), path)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	db := store.DB()
	for _, stmt := range []string{
		`DROP INDEX idx_audit_batch`,
		`DROP INDEX idx_audit_head`,
		`DROP INDEX idx_audit_head_machine`,
		`DROP INDEX idx_audit_head_env`,
		`ALTER TABLE audit_logs DROP COLUMN batch_id`,
		`PRAGMA user_version = 1`,
		// v1 の時代に書かれた監査行。
		`INSERT INTO audit_logs (at, actor, action, result) VALUES (1000, 'system', 'secret.read', 'success')`,
	} {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	// 戻し方が正しいこと(本物の v1 と同じ形であること)を確かめておく。
	if got, want := schemaShape(t, db), schemaShape(t, newV1Store(t).DB()); !slices.Equal(got, want) {
		t.Fatalf("test setup: the downgraded file is not a v1 database:\ngot:  %v\nwant: %v", got, want)
	}
	before := keyringAndUsers(t, db)
	auditBefore := queryStrings(t, db, `SELECT COUNT(*) FROM audit_logs`)
	if len(before) < 2 {
		t.Fatalf("test setup: keyring and users = %v, want a keyring and an admin", before)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := cmdInit(t.Context(), []string{"-db", path, "-migrate-only"}); err != nil {
		t.Fatalf("cmdInit --migrate-only on a v1 database: %v", err)
	}

	// OpenStore はバージョンが合わなければ開かない。
	upgraded, err := OpenStore(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenStore after --migrate-only: %v", err)
	}
	defer upgraded.Close()

	assertUserVersion(t, upgraded.DB(), schemaVersion)
	if got, want := schemaShape(t, upgraded.DB()), schemaShape(t, newTestStore(t).DB()); !slices.Equal(got, want) {
		t.Errorf("the upgraded file differs from a fresh database:\ngot:  %v\nwant: %v", got, want)
	}
	if after := keyringAndUsers(t, upgraded.DB()); !slices.Equal(before, after) {
		t.Errorf("--migrate-only changed the keyring or the users:\nbefore: %v\nafter:  %v", before, after)
	}
	// 移行そのものは監査行を足しも減らしもしない。
	if after := queryStrings(t, upgraded.DB(), `SELECT COUNT(*) FROM audit_logs`); !slices.Equal(auditBefore, after) {
		t.Errorf("audit rows = %v after --migrate-only, want %v", after, auditBefore)
	}
}

// queryPlan は EXPLAIN QUERY PLAN の detail 列を 1 つの文字列にして返す。
func queryPlan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()

	var details []string
	for rows.Next() {
		var (
			id, parent, notUsed int
			detail              string
		)
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan: %v", err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return strings.Join(details, "; ")
}

// **部分インデックスが、意図した問い合わせで実際に使われる。**
//
// インデックスが「在る」ことは TestMigrateFreshAndUpgradedSchemasMatch が
// 見ている。部分インデックスは、問い合わせの WHERE が索引の WHERE を含意すると
// プランナが判断できたときだけ使われる(`batch_id = ?` は `IS NOT NULL` を
// 含意する)。条件を書き換えると、在るのに使われない索引になる。
// 「設定した」ではなく「効いている」を確かめる。
func TestAuditBatchIndexesAreUsed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query string
		index string
		// noSort が真なら、並べ替えも索引で済むこと(一時 B-tree を作らない)。
		noSort bool
	}{
		{
			name:  "members of a batch",
			query: `SELECT id FROM audit_logs WHERE batch_id = ? ORDER BY id`,
			index: "idx_audit_batch",
		},
		{
			name:  "size of a batch",
			query: `SELECT COUNT(*) FROM audit_logs WHERE batch_id = ?`,
			index: "idx_audit_batch",
		},
		// 一覧用の索引は `batch_id IS NULL` を条件に持つ。問い合わせがその条件を
		// 書いていなければ使われない。
		{
			name:   "list rows of an environment, newest first",
			query:  `SELECT id FROM audit_logs WHERE batch_id IS NULL AND target_environment_id = ? ORDER BY at DESC, id DESC LIMIT 50`,
			index:  "idx_audit_head_env",
			noSort: true,
		},
		{
			name:   "list rows of a machine, newest first",
			query:  `SELECT id FROM audit_logs WHERE batch_id IS NULL AND actor_machine_id = ? ORDER BY at DESC, id DESC LIMIT 50`,
			index:  "idx_audit_head_machine",
			noSort: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := queryPlan(t, newTestStore(t).DB(), tt.query, int64(1))
			if !strings.Contains(plan, tt.index) {
				t.Errorf("plan = %q, want it to use %s", plan, tt.index)
			}
			if tt.noSort && strings.Contains(plan, "TEMP B-TREE") {
				t.Errorf("plan = %q, want the index to provide the order", plan)
			}
		})
	}
}

// **bulk fetch の監査は、batch のどの行が失敗しても 1 行も残らない。**
//
// 既存の TestAPIBulkSecretReadAuditIsAtomic は target を見るトリガで 2 行目を
// 落としている。batch では先頭行と後続の行で INSERT の中身が違う(batch_id の
// 有無)ので、両方の位置で確かめる。先頭行だけが残ると、画面には「1 件だけ
// 読んだ」単独の行として見え、返していない secret の読み取りが記録に残る。
func TestAPIBulkSecretReadBatchIsAllOrNothing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		when string
	}{
		{"the head row fails", `NEW.action = 'secret.read' AND NEW.batch_id IS NULL`},
		{"a later row fails", `NEW.batch_id IS NOT NULL`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newAPIFixture(t)
			token := f.token(t)

			if _, err := f.store.DB().ExecContext(t.Context(), `
				CREATE TRIGGER fail_batch_row BEFORE INSERT ON audit_logs WHEN `+tt.when+`
				BEGIN SELECT RAISE(ABORT, 'audit write failed'); END`); err != nil {
				t.Fatalf("create trigger: %v", err)
			}

			w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body %q)", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "postgres://") || strings.Contains(w.Body.String(), "t0ken") {
				t.Errorf("the response leaked a secret: %q", w.Body.String())
			}
			if rows := auditBatchRows(t, f.store.DB(), ActionSecretRead); len(rows) != 0 {
				t.Errorf("secret.read rows after a failed batch = %v, want none (all or nothing)", rows)
			}
		})
	}
}

// **同じ machine の 2 回の bulk fetch は、別々の batch になる。**
//
// 同じ秒・同じ machine・同じ送信元でも、呼び出しが違えば先頭行が違う
// (v1 の行を埋め戻さなかった理由が、v2 では事実として区別できること)。
// 2 回目の後続行が 1 回目の先頭行を指すと、画面では 1 回の読み取りに見える。
func TestAPITwoBulkSecretReadsAreTwoBatches(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	const fetches = 2
	for i := range fetches {
		if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusOK {
			t.Fatalf("bulk fetch %d: status = %d, want 200", i+1, w.Code)
		}
	}

	rows := auditBatchRows(t, f.store.DB(), ActionSecretRead)
	noBatch, members := splitBatches(rows)
	if len(noBatch) != fetches || len(members) != fetches {
		t.Fatalf("head rows = %v, batches = %v, want %d of each", noBatch, members, fetches)
	}
	// fixture の key は 2 つなので、各 batch は先頭行 + 後続 1 行である。
	perFetch := len(rows) / fetches
	for _, head := range noBatch {
		ids := members[head]
		if len(ids) != perFetch-1 {
			t.Errorf("batch %d = %v, want %d rows after the head", head, ids, perFetch-1)
		}
		for _, id := range ids {
			if id <= head {
				t.Errorf("batch %d: row %d was written before its head row", head, id)
			}
		}
	}
	// 2 回目の行は、1 回目の先頭行を指さない。
	if last := rows[len(rows)-1]; last.Batch.Int64 != noBatch[fetches-1] {
		t.Errorf("the last row points at %v, want the head of the second fetch (%d)", last.Batch, noBatch[fetches-1])
	}
}

// **拒否された読み取り(403)の行は、どの batch にも属さない。**
//
// 直前に同じ machine の bulk fetch(batch)があっても、失敗の行はそこに
// 混ざらず、単独の行として一覧に出る。成功した読み取りの折りたたみの中に
// 拒否が隠れると、探索行為の手掛かりが画面から消える。
func TestAPIDeniedSecretReadIsNotPartOfABatch(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusOK {
		t.Fatalf("bulk fetch: status = %d, want 200", w.Code)
	}
	if _, err := f.store.DB().ExecContext(t.Context(),
		`DELETE FROM machine_grants WHERE machine_id = ?`, f.machineID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusForbidden {
		t.Fatalf("denied bulk fetch: status = %d, want 403", w.Code)
	}

	var denied auditBatchRow
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT id, batch_id FROM audit_logs WHERE action = ? AND result = ?`,
		string(ActionSecretRead), string(ResultFailure),
	).Scan(&denied.ID, &denied.Batch); err != nil {
		t.Fatalf("select the denied row: %v", err)
	}
	if denied.Batch.Valid {
		t.Errorf("denied row %d: batch_id = %v, want NULL", denied.ID, denied.Batch)
	}
	_, members := splitBatches(auditBatchRows(t, f.store.DB(), ""))
	if ids, ok := members[denied.ID]; ok {
		t.Errorf("rows %v point at the denied row %d as their head", ids, denied.ID)
	}
}
