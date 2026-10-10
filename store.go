package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store は hokora の SQLite データベースへのハンドルである。
type Store struct {
	db *sql.DB
}

// PRAGMA は SQLite の接続単位の設定であり、database/sql は複数の物理接続を開き、
// 障害時には接続を再生成する。したがって起動時に 1 接続だけで PRAGMA を実行しても
// 他の接続には効かない。foreign_keys はデフォルト OFF なので、これを取りこぼすと
// ON DELETE RESTRICT による保護(THREAT_MODEL §11)が成立しない。
//
// modernc.org/sqlite は DSN の _pragma= を newConn から各物理接続の確立時に
// 適用する。全接続で効いていることは store_test.go で実証する(DESIGN §3.1)。
var connectPragmas = []string{
	"journal_mode(WAL)",
	"foreign_keys(ON)",
	"busy_timeout(5000)",
	"synchronous(FULL)",
}

// maxOpenConns はプールが開く物理接続の上限である。単一プロセス・単一ファイルで
// あり、書き込みは SQLite 側で直列化されるので、接続数を絞ってロック競合を減らす。
const maxOpenConns = 4

// dataSourceName は path に対する DSN を組み立てる。
func dataSourceName(path string) string {
	q := url.Values{}
	for _, p := range connectPragmas {
		q.Add("_pragma", p)
	}
	return "file:" + url.PathEscape(path) + "?" + q.Encode()
}

// dataSourceNameReadOnly は path を読み取り専用で開く DSN を組み立てる。
//
// **WAL の pragma を付けない。** dataSourceName は journal_mode(WAL) を適用
// するが、それを読み取り専用で開きたい対象に適用すると、対象ファイルへ書き込みが
// 走って -wal / -shm の随伴ファイルを生む。スナップショットを副作用なく点検する
// 用途(バックアップの検証)では、mode=ro で開いて一切書き込ませない。
func dataSourceNameReadOnly(path string) string {
	return "file:" + url.PathEscape(path) + "?mode=ro"
}

// OpenStore は DB を開き、スキーマのバージョンが本バイナリと一致することを
// 確認する。一致しない DB(未初期化を含む)はエラーにする。
//
// バージョン検査を「移行するとき」ではなく「開くとき」に置くのは、serve /
// unseal / get など DB に触る全経路を 1 箇所で守るためである。移行を行う
// コマンドだけが検査していると、移行しない経路が素通りする。
func OpenStore(ctx context.Context, path string) (*Store, error) {
	store, err := openDatabase(ctx, path)
	if err != nil {
		return nil, err
	}

	version, err := schemaVersionOf(ctx, store.db)
	if err != nil {
		return nil, errors.Join(err, store.Close())
	}
	if version != schemaVersion {
		return nil, errors.Join(
			fmt.Errorf("database schema version is %d, want %d: run `hokora init`", version, schemaVersion),
			store.Close(),
		)
	}
	return store, nil
}

// OpenStoreReadOnly は DB を読み取り専用で開き、スキーマのバージョンが本バイナリと
// 一致することを確認する。
//
// **対象ファイルを一切変更しない**(mode=ro。WAL の pragma を付けないので
// -wal / -shm の随伴ファイルも作らない)。バックアップのスナップショットを副作用
// なく点検する用途に使う。書き込み経路の OpenStore と別口だが、DSN の構築と
// スキーマ検査をこの層へ集約し、コマンド側が生の sql.Open に手を伸ばさないようにする。
func OpenStoreReadOnly(ctx context.Context, path string) (*Store, error) {
	store, err := openDatabaseDSN(ctx, dataSourceNameReadOnly(path))
	if err != nil {
		return nil, err
	}

	version, err := schemaVersionOf(ctx, store.db)
	if err != nil {
		return nil, errors.Join(err, store.Close())
	}
	if version != schemaVersion {
		// OpenStore と違い「run `hokora init`」は促さない。点検対象は稼働 DB では
		// なくバックアップのスナップショットであり、そこへ init を促すのは誤誘導。
		return nil, errors.Join(
			fmt.Errorf("database schema version is %d, want %d", version, schemaVersion),
			store.Close(),
		)
	}
	return store, nil
}

// openDatabase は接続だけを確立し、スキーマのバージョンを検査しない。
// スキーマ未適用の DB を扱ってよいのは init(Migrate)だけなので、直接呼ぶのは
// init と OpenStore に限る。他の経路は必ず OpenStore を通す。
func openDatabase(ctx context.Context, path string) (*Store, error) {
	return openDatabaseDSN(ctx, dataSourceName(path))
}

// openDatabaseDSN は与えられた DSN で接続を確立する(スキーマのバージョンは
// 検査しない)。DSN の違い(読み書き / 読み取り専用)だけを呼び出し側に委ね、
// プール設定と接続確認をここへ集約する。
func openDatabaseDSN(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)

	// PingContext は物理接続を 1 本張るので、DSN の PRAGMA が通らない
	// (壊れたファイル等)こともここで分かる。
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("connect to database: %w", err), db.Close())
	}
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }

// closeStore は defer から呼び、Close の失敗を最初のエラーとして拾う。
//
// Close の失敗は WAL のチェックポイント漏れ等を示すので握りつぶさない。
// ただし本体の処理が既に失敗しているなら、そちらを優先する。
func closeStore(s *Store, err *error) {
	if cerr := s.Close(); cerr != nil && *err == nil {
		*err = fmt.Errorf("close database: %w", cerr)
	}
}

// withTx はトランザクションを開き、fn が成功したら commit する。
//
// **fail closed の監査は本体の処理と同じトランザクションに載せる**
// (THREAT_MODEL §10.4)。そのため書き込み経路はほぼ全てこの形になる。
// begin / rollback / commit を書き写すたびに rollback を忘れる余地が
// 生まれるので、1 箇所に集める。
func withTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, ignoreTxDone(tx.Rollback()))
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// ---- keyring ----

// ErrKeyringMissing は keyring 行が無いことを示す。`hokora init` が済んで
// いない DB を unseal しようとした場合に返る。
var ErrKeyringMissing = errors.New("keyring not found: run `hokora init`")

// querier は *sql.DB と *sql.Tx の共通部分である(読み取り側)。
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// LoadKeyring は keyring を読む。行は常に 1 行のみ(id = 1 の CHECK 制約)。
func LoadKeyring(ctx context.Context, q querier) (*Keyring, error) {
	var (
		kr                   Keyring
		createdAt, updatedAt int64
	)
	err := q.QueryRowContext(ctx, `
		SELECT dek_wrapped, dek_nonce, kdf_salt, dek_version, created_at, updated_at
		FROM keyring WHERE id = 1`,
	).Scan(&kr.DEKWrapped, &kr.DEKNonce, &kr.KDFSalt, &kr.DEKVersion, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrKeyringMissing
	}
	if err != nil {
		return nil, fmt.Errorf("load keyring: %w", err)
	}
	kr.CreatedAt = time.Unix(createdAt, 0).UTC()
	kr.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return &kr, nil
}

// InsertKeyring は keyring を作る。既に存在する場合は UNIQUE 制約で失敗する
// (id = 1 固定)。**上書きしない**のは、既存の DEK を失うと全ての secret が
// 復号不能になるためである。
func InsertKeyring(ctx context.Context, ex execer, kr *Keyring) error {
	_, err := ex.ExecContext(ctx, `
		INSERT INTO keyring (id, dek_wrapped, dek_nonce, kdf_salt, dek_version, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?)`,
		kr.DEKWrapped, kr.DEKNonce, kr.KDFSalt, kr.DEKVersion,
		kr.CreatedAt.Unix(), kr.UpdatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("insert keyring: %w", err)
	}
	return nil
}

// UpdateKeyringWrap は DEK のラップだけを差し替える(rotate-master 用)。
//
// **dek_version は変えない。** MK のローテーションは DEK を変えないので、
// 既存の item_versions は再暗号化不要である(DESIGN §6.7)。
func UpdateKeyringWrap(ctx context.Context, ex execer, kr *Keyring) error {
	res, err := ex.ExecContext(ctx, `
		UPDATE keyring SET dek_wrapped = ?, dek_nonce = ?, kdf_salt = ?, updated_at = ?
		WHERE id = 1`,
		kr.DEKWrapped, kr.DEKNonce, kr.KDFSalt, kr.UpdatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("update keyring: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update keyring: %w", err)
	}
	if n != 1 {
		return ErrKeyringMissing
	}
	return nil
}

// ---- Machine API のクエリ ----
//
// **全ての取得クエリで、全祖先の deleted_at IS NULL を検査する**
// (AGENTS.md ルール 58)。project を論理削除しても配下の environment /
// item の行は残るため、これを怠ると「削除した project の secret が
// Machine API から取得できる」状態になる(THREAT_MODEL §11.1)。

// ErrNotFound は対象が存在しない(または論理削除済みである)ことを示す。
//
// **呼び出し側はこれを「grant が無い」と同じ扱いにする。** 区別すると、
// project / environment / item の存在情報が漏れる(AGENTS.md ルール 54)。
var ErrNotFound = errors.New("not found")

// FindMachineByClientID は client_id で machine を引く。
//
// **disabled も含めて返す。** 認証側で「存在しない」と「無効」を同じ
// 応答に潰す必要があり、ここで振り分けると dummy hash 計算の機会を失う。
func FindMachineByClientID(ctx context.Context, q querier, clientID string) (*Machine, error) {
	var (
		m          Machine
		disabled   int
		created    int64
		updated    int64
		lastAuthAt sql.NullInt64
	)
	err := q.QueryRowContext(ctx, `
		SELECT id, client_id, secret_hash, name, disabled, created_at, updated_at, last_auth_at
		FROM machines WHERE client_id = ?`, clientID,
	).Scan(&m.ID, &m.ClientID, &m.SecretHash, &m.Name, &disabled, &created, &updated, &lastAuthAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find machine: %w", err)
	}

	m.Disabled = disabled != 0
	m.CreatedAt = time.Unix(created, 0).UTC()
	m.UpdatedAt = time.Unix(updated, 0).UTC()
	if lastAuthAt.Valid {
		t := time.Unix(lastAuthAt.Int64, 0).UTC()
		m.LastAuthAt = &t
	}
	return &m, nil
}

// MachineIsActive は machine が有効かどうかを返す。
//
// **リクエストごとに呼ぶ。** トークンは認証の証明であって認可の証明では
// ないため、disabled は毎回読み直す(DESIGN §4.5)。
func MachineIsActive(ctx context.Context, q querier, machineID int64) (bool, error) {
	var disabled int
	err := q.QueryRowContext(ctx,
		`SELECT disabled FROM machines WHERE id = ?`, machineID).Scan(&disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check machine: %w", err)
	}
	return disabled == 0, nil
}

// EnvironmentRef は解決済みの project / environment である。
// 監査ログの immutable ID と表示用文字列の両方をここから作る。
type EnvironmentRef struct {
	ProjectID     int64
	EnvironmentID int64
	ProjectSlug   string
	EnvSlug       string
}

// ResolveEnvironment は project slug と environment slug から ID を引く。
//
// **project と environment の両方の deleted_at を検査する。** environment
// 側だけを見ると、project を論理削除しても配下が生き残る。
func ResolveEnvironment(ctx context.Context, q querier, projectSlug, envSlug string) (*EnvironmentRef, error) {
	ref := EnvironmentRef{ProjectSlug: projectSlug, EnvSlug: envSlug}
	err := q.QueryRowContext(ctx, `
		SELECT p.id, e.id
		FROM environments e
		JOIN projects p ON p.id = e.project_id
		WHERE p.slug = ? AND e.slug = ?
		  AND p.deleted_at IS NULL AND e.deleted_at IS NULL`,
		projectSlug, envSlug,
	).Scan(&ref.ProjectID, &ref.EnvironmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve environment: %w", err)
	}
	return &ref, nil
}

// FindEnvironmentByID は environment を ID から引く。
//
// **祖先の deleted_at を検査する**(ルール 58)。プルダウンには生きた
// environment しか出さないが、POST は細工された ID を運びうるので、ここで
// 論理削除済みを弾く。
func FindEnvironmentByID(ctx context.Context, q querier, environmentID int64) (*EnvironmentRef, error) {
	ref := EnvironmentRef{EnvironmentID: environmentID}
	err := q.QueryRowContext(ctx, `
		SELECT p.id, p.slug, e.slug
		FROM environments e
		JOIN projects p ON p.id = e.project_id
		WHERE e.id = ? AND e.deleted_at IS NULL AND p.deleted_at IS NULL`,
		environmentID).Scan(&ref.ProjectID, &ref.ProjectSlug, &ref.EnvSlug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find environment: %w", err)
	}
	return &ref, nil
}

// GrantableEnvironment は grant 付与のプルダウンに出す 1 件である。
type GrantableEnvironment struct {
	EnvironmentID int64
	ProjectSlug   string
	EnvSlug       string
}

// ListGrantableEnvironments は grant を付与できる environment を全て返す。
func ListGrantableEnvironments(ctx context.Context, db *sql.DB) (_ []GrantableEnvironment, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT e.id, p.slug, e.slug
		FROM environments e
		JOIN projects p ON p.id = e.project_id
		WHERE e.deleted_at IS NULL AND p.deleted_at IS NULL
		ORDER BY p.slug, e.slug`)
	if err != nil {
		return nil, fmt.Errorf("list grantable environments: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list grantable environments: %w", cerr)
		}
	}()

	var out []GrantableEnvironment
	for rows.Next() {
		var g GrantableEnvironment
		if err := rows.Scan(&g.EnvironmentID, &g.ProjectSlug, &g.EnvSlug); err != nil {
			return nil, fmt.Errorf("scan grantable environment: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// HasGrant は machine が environment への grant を持つかを返す。
//
// **grant は物理削除される。** 削除された時点で次のリクエストから効く
// (DESIGN §4.5)。
func HasGrant(ctx context.Context, q querier, machineID, environmentID int64) (bool, error) {
	var one int
	err := q.QueryRowContext(ctx, `
		SELECT 1 FROM machine_grants WHERE machine_id = ? AND environment_id = ?`,
		machineID, environmentID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check grant: %w", err)
	}
	return true, nil
}

// EncryptedSecret は暗号化されたままの secret 1 件である。
// 復号は Vault の read lock 内で行う(C1)ため、ここでは値を触らない。
type EncryptedSecret struct {
	ItemID     int64
	Key        string
	Version    int64
	ValueEnc   []byte
	Nonce      []byte
	DEKVersion int64
}

// selectSecretsSQL は environment 配下の secret を、全祖先の deleted_at を
// 検査しつつ取得する。
//
// items.current_version と item_versions.version の JOIN で最新版のみを引く。
// **version パラメータは受け取らない**(DESIGN §8.1)。
//
//nolint:gosec // G101: 認証情報ではなく SQL である(secret という語に反応している)
const selectSecretsSQL = `
SELECT i.id, i.key, v.version, v.value_enc, v.nonce, v.dek_version
FROM items i
JOIN item_versions v ON v.item_id = i.id AND v.version = i.current_version
JOIN environments e ON e.id = i.environment_id
JOIN projects p ON p.id = e.project_id
WHERE i.environment_id = ?
  AND i.deleted_at IS NULL
  AND e.deleted_at IS NULL
  AND p.deleted_at IS NULL
  AND i.current_version > 0`

// ListEncryptedSecrets は environment 配下の全 secret を暗号文のまま返す。
func ListEncryptedSecrets(ctx context.Context, db *sql.DB, environmentID int64) (_ []EncryptedSecret, err error) {
	rows, err := db.QueryContext(ctx, selectSecretsSQL+` ORDER BY i.key`, environmentID)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list secrets: %w", cerr)
		}
	}()

	var secrets []EncryptedSecret
	for rows.Next() {
		var s EncryptedSecret
		if err := rows.Scan(&s.ItemID, &s.Key, &s.Version, &s.ValueEnc, &s.Nonce, &s.DEKVersion); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		secrets = append(secrets, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	return secrets, nil
}

// GetEncryptedSecret は 1 件の secret を暗号文のまま返す。
func GetEncryptedSecret(ctx context.Context, q querier, environmentID int64, key string) (*EncryptedSecret, error) {
	var s EncryptedSecret
	err := q.QueryRowContext(ctx, selectSecretsSQL+` AND i.key = ?`, environmentID, key).
		Scan(&s.ItemID, &s.Key, &s.Version, &s.ValueEnc, &s.Nonce, &s.DEKVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}
	return &s, nil
}

// ---- Web UI の一覧・CRUD ----
//
// **一覧は平文を返さない**(AGENTS.md ルール 41)。マスクは表示上の処理では
// なく、サーバーが値を返さないことで担保する。ここで返す構造体に平文の
// フィールドが無いこと自体が、その保証である。

// ProjectRow はダッシュボードの 1 行である。
type ProjectRow struct {
	ID    int64
	Slug  string
	Name  string
	Envs  int
	Items int
}

// ListProjects は論理削除されていない project を返す。
func ListProjects(ctx context.Context, db *sql.DB) (_ []ProjectRow, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.slug, p.name,
		       (SELECT COUNT(*) FROM environments e
		        WHERE e.project_id = p.id AND e.deleted_at IS NULL),
		       (SELECT COUNT(*) FROM items i
		        JOIN environments e ON e.id = i.environment_id
		        WHERE e.project_id = p.id AND e.deleted_at IS NULL AND i.deleted_at IS NULL)
		FROM projects p
		WHERE p.deleted_at IS NULL
		ORDER BY p.slug`)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list projects: %w", cerr)
		}
	}()

	var out []ProjectRow
	for rows.Next() {
		var p ProjectRow
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.Envs, &p.Items); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FindProject は slug から project を引く(論理削除済みは見つからない)。
func FindProject(ctx context.Context, q querier, slug string) (*Project, error) {
	var p Project
	err := q.QueryRowContext(ctx,
		`SELECT id, slug, name FROM projects WHERE slug = ? AND deleted_at IS NULL`, slug).
		Scan(&p.ID, &p.Slug, &p.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find project: %w", err)
	}
	return &p, nil
}

// EnvironmentRow は project 詳細の 1 行である。
type EnvironmentRow struct {
	ID    int64
	Slug  string
	Name  string
	Items int
}

// ListEnvironments は project 配下の environment を返す。
func ListEnvironments(ctx context.Context, db *sql.DB, projectID int64) (_ []EnvironmentRow, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT e.id, e.slug, e.name,
		       (SELECT COUNT(*) FROM items i
		        WHERE i.environment_id = e.id AND i.deleted_at IS NULL)
		FROM environments e
		WHERE e.project_id = ? AND e.deleted_at IS NULL
		ORDER BY e.slug`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list environments: %w", cerr)
		}
	}()

	var out []EnvironmentRow
	for rows.Next() {
		var e EnvironmentRow
		if err := rows.Scan(&e.ID, &e.Slug, &e.Name, &e.Items); err != nil {
			return nil, fmt.Errorf("scan environment: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ItemRow は item 一覧の 1 行である。**値は含まない。**
type ItemRow struct {
	ID        int64
	Key       string
	Version   int64
	UpdatedAt time.Time
	CreatedBy string
}

// ListItems は environment 配下の item を返す。**平文も暗号文も返さない。**
//
// **祖先の deleted_at もここで検査する**(AGENTS.md ルール 58)。呼び出し側が
// 先に ResolveEnvironment を通しているかどうかに依存しない ── 依存すると、
// その手順を踏まない呼び出しが増えた時点で、削除済み project の item が
// 一覧に出る。
func ListItems(ctx context.Context, db *sql.DB, environmentID int64) (_ []ItemRow, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT i.id, i.key, i.current_version, i.updated_at,
		       COALESCE((SELECT v.created_by FROM item_versions v
		                 WHERE v.item_id = i.id AND v.version = i.current_version), '')
		FROM items i
		JOIN environments e ON e.id = i.environment_id
		JOIN projects p ON p.id = e.project_id
		WHERE i.environment_id = ?
		  AND i.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL
		ORDER BY i.key`, environmentID)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list items: %w", cerr)
		}
	}()

	var out []ItemRow
	for rows.Next() {
		var (
			it        ItemRow
			updatedAt int64
		)
		if err := rows.Scan(&it.ID, &it.Key, &it.Version, &updatedAt, &it.CreatedBy); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		it.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		out = append(out, it)
	}
	return out, rows.Err()
}

// VersionRow は履歴の 1 行である。**値は含まない。**
type VersionRow struct {
	Version   int64
	CreatedAt time.Time
	CreatedBy string
	Current   bool
}

// ListItemVersions は item の履歴を新しい順に返す。
//
// **祖先の deleted_at を検査する**(ルール 58)。FindItem / GetItemVersion は
// 検査しているので、ここだけ抜けていると非対称になり、見落としやすい。
func ListItemVersions(ctx context.Context, db *sql.DB, itemID int64) (_ []VersionRow, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT v.version, v.created_at, v.created_by, (v.version = i.current_version)
		FROM item_versions v
		JOIN items i ON i.id = v.item_id
		JOIN environments e ON e.id = i.environment_id
		JOIN projects p ON p.id = e.project_id
		WHERE v.item_id = ?
		  AND i.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL
		ORDER BY v.version DESC`, itemID)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list versions: %w", cerr)
		}
	}()

	var out []VersionRow
	for rows.Next() {
		var (
			v         VersionRow
			createdAt int64
			current   int
		)
		if err := rows.Scan(&v.Version, &createdAt, &v.CreatedBy, &current); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		v.CreatedAt = time.Unix(createdAt, 0).UTC()
		v.Current = current != 0
		out = append(out, v)
	}
	return out, rows.Err()
}

// FindItem は key から item を引く(祖先の deleted_at も検査する)。
func FindItem(ctx context.Context, q querier, environmentID int64, key string) (*Item, error) {
	var it Item
	err := q.QueryRowContext(ctx, `
		SELECT i.id, i.key, i.current_version
		FROM items i
		JOIN environments e ON e.id = i.environment_id
		JOIN projects p ON p.id = e.project_id
		WHERE i.environment_id = ? AND i.key = ?
		  AND i.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL`,
		environmentID, key).Scan(&it.ID, &it.Key, &it.CurrentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find item: %w", err)
	}
	it.EnvironmentID = environmentID
	return &it, nil
}

// GetItemVersion は特定バージョンの暗号文を返す(履歴の平文表示に使う)。
func GetItemVersion(ctx context.Context, q querier, itemID, version int64) (*EncryptedSecret, error) {
	s := EncryptedSecret{ItemID: itemID, Version: version}
	err := q.QueryRowContext(ctx, `
		SELECT i.key, v.value_enc, v.nonce, v.dek_version
		FROM item_versions v
		JOIN items i ON i.id = v.item_id
		JOIN environments e ON e.id = i.environment_id
		JOIN projects p ON p.id = e.project_id
		WHERE v.item_id = ? AND v.version = ?
		  AND i.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL`,
		itemID, version).Scan(&s.Key, &s.ValueEnc, &s.Nonce, &s.DEKVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get item version: %w", err)
	}
	return &s, nil
}

// MachineRow は Machine 一覧の 1 行である。**secret_hash は含まない。**
type MachineRow struct {
	ID         int64
	ClientID   string
	Name       string
	Disabled   bool
	LastAuthAt *time.Time
	Grants     []GrantRow
}

// GrantRow は grant 1 件である。
type GrantRow struct {
	EnvironmentID int64
	ProjectSlug   string
	EnvSlug       string
}

// ListMachines は machine を grant つきで返す。
func ListMachines(ctx context.Context, db *sql.DB) (_ []MachineRow, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, client_id, name, disabled, last_auth_at FROM machines ORDER BY client_id`)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list machines: %w", cerr)
		}
	}()

	var out []MachineRow
	for rows.Next() {
		var (
			m        MachineRow
			disabled int
			lastAuth sql.NullInt64
		)
		if err := rows.Scan(&m.ID, &m.ClientID, &m.Name, &disabled, &lastAuth); err != nil {
			return nil, fmt.Errorf("scan machine: %w", err)
		}
		m.Disabled = disabled != 0
		if lastAuth.Valid {
			at := time.Unix(lastAuth.Int64, 0).UTC()
			m.LastAuthAt = &at
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}

	// grant は件数が少ないので、machine ごとではなく一括で引いて割り当てる
	// (N+1 を避ける)。
	grants, err := listGrants(ctx, db)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Grants = grants[out[i].ID]
	}
	return out, nil
}

func listGrants(ctx context.Context, db *sql.DB) (_ map[int64][]GrantRow, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT g.machine_id, g.environment_id, p.slug, e.slug
		FROM machine_grants g
		JOIN environments e ON e.id = g.environment_id
		JOIN projects p ON p.id = e.project_id
		WHERE e.deleted_at IS NULL AND p.deleted_at IS NULL
		ORDER BY p.slug, e.slug`)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list grants: %w", cerr)
		}
	}()

	out := map[int64][]GrantRow{}
	for rows.Next() {
		var (
			machineID int64
			g         GrantRow
		)
		if err := rows.Scan(&machineID, &g.EnvironmentID, &g.ProjectSlug, &g.EnvSlug); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}
		out[machineID] = append(out[machineID], g)
	}
	return out, rows.Err()
}

// UserRow はユーザー一覧の 1 行である。**password_hash は含まない。**
type UserRow struct {
	ID           int64
	Username     string
	MustChangePW bool
	Disabled     bool
	CreatedAt    time.Time
}

// ListUsers はユーザーを返す。
func ListUsers(ctx context.Context, db *sql.DB) (_ []UserRow, err error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, username, must_change_pw, disabled, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list users: %w", cerr)
		}
	}()

	var out []UserRow
	for rows.Next() {
		var (
			u                    UserRow
			mustChange, disabled int
			createdAt            int64
		)
		if err := rows.Scan(&u.ID, &u.Username, &mustChange, &disabled, &createdAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.MustChangePW = mustChange != 0
		u.Disabled = disabled != 0
		u.CreatedAt = time.Unix(createdAt, 0).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}

// AuditRow は監査ログ画面の 1 行である。
//
// **Actor / Target は表示用に解決済みの文字列である。** 監査ログに記録するのは
// immutable な ID(`user:1` / `machine:3`)であって名前ではない(ルール 24)。
// 名前は user / machine の**現在の値**を JOIN で引いて併記する。
type AuditRow struct {
	ID         int64
	At         time.Time
	Actor      string
	Action     string
	Target     string
	Result     string
	RemoteAddr string
	Detail     string

	// Batch は、この行が対象にする key である。**key を対象にする行は、1 件でも
	// ここに入る**(そのとき Target は 'project/env' までで、Detail は空になる)。
	// bulk fetch(「key ごとに 1 行」)では、同じ呼び出しで書かれた行が、先頭行
	// 自身を含めて並ぶ。key を対象にしない行(ログイン等)では空である。
	//
	// 一覧に出るのは batch の先頭行だけで、残りはここに畳まれる。**行そのものは
	// DB に key の数だけある**(AGENTS.md ルール 23)。まとめるのは表示だけである。
	//
	// 一覧では auditBatchInlineLimit 件までしか載せない。BatchSize は省略した分も
	// 含む実数である。
	Batch     []AuditBatchItem
	BatchSize int
}

// BatchHidden は、Batch に載せていない key の数を返す。
func (r AuditRow) BatchHidden() int {
	return r.BatchSize - len(r.Batch)
}

// AuditBatchItem は batch の中の 1 行(1 つの key の読み取り)である。
type AuditBatchItem struct {
	Target string // 記録時点の表示文字列 'myapp/prod/DATABASE_URL'
	Detail string
}

// AuditFilter は監査ログ一覧の絞り込み条件である。ゼロ値は「絞り込まない」。
//
// **batch の全行に共通する条件だけを持つ。** 一覧は batch の先頭行だけを拾う
// (`batch_id IS NULL`)ので、key のように行ごとに違う条件をここへ足すと、
// 先頭行でない key の読み取りが一覧から消える(DESIGN §5.2)。
type AuditFilter struct {
	// From <= at < To。nil なら、その側は絞り込まない。
	//
	// **「指定なし」を time.Time のゼロ値で表さない。** ゼロ値(西暦 1 年 1 月
	// 1 日)は正当な入力から作れてしまう(終了日 0000-12-31 の翌日)。そうすると
	// 絞り込みが黙って外れ、利用者は絞り込めているつもりで全件を見る。
	From, To *time.Time

	// 実行者。3 つのうち高々 1 つを指定する。
	ActorUserID    *int64
	ActorMachineID *int64
	ActorAnonymous bool

	Action Action // 空なら全ての操作
	Result Result // 空なら成功と失敗の両方

	EnvironmentID *int64 // 対象の環境
}

// AuditCursor は一覧の中の位置である(並び順のキー at, id)。
type AuditCursor struct {
	At int64
	ID int64
}

// AuditQuery は監査ログ一覧の 1 ページ分の問い合わせである。
//
// Before / After はどちらか一方だけを指定する。両方 nil なら最新のページ。
type AuditQuery struct {
	Filter AuditFilter
	Limit  int
	Before *AuditCursor // この位置より古い行
	After  *AuditCursor // この位置より新しい行
}

// AuditPage は監査ログ一覧の 1 ページである。
type AuditPage struct {
	Rows []AuditRow
	// Older / Newer は、このページの外にまだ行があるときだけ非 nil になる。
	// 値はページの端の行の位置で、そのまま次の AuditQuery に渡せる。
	Older *AuditCursor
	Newer *AuditCursor
}

// listAuditLogsSQL は監査行に、主体・対象の現在の名前を左外部結合する。
//
// audit_logs は FK を持たない(ルール 57)ので、参照先が引けないことは正常で
// ある。**削除された project / environment も表示できなければならない**ため、
// ここでは `deleted_at IS NULL` で絞らない(ルール 58 は secret の取得経路の
// 話であり、監査は「その時点で何が起きたか」の記録である)。
//
// 結合先が 4 つあるのは、対象が machine / user / environment のどれになるかが
// action で変わるためである。actor 側は user と machine の両方が同時に立つこと
// はない(AuditEntry.validate が拒否する)。
// 列は「行そのもの」「actor」「対象」「batch の後続行の数」の順に並べる。対象の
// 列は auditTargetRefs のフィールド順と一致させ、そのまま Scan する。
//
// 最後の列は、この行を先頭とする batch の後続行の数である(idx_audit_batch で
// 引く)。単独の行では 0 になる。
const listAuditLogsSQL = `
	SELECT a.id, a.at, a.action, a.result, COALESCE(a.remote_addr, ''), COALESCE(a.detail, ''),
	       a.actor, COALESCE(au.username, ''), COALESCE(am.name, ''),
	       COALESCE(a.target, ''),
	       a.target_user_id, COALESCE(tu.username, ''),
	       a.target_machine_id, COALESCE(tm.name, ''),
	       COALESCE(tp.slug, ''), COALESCE(te.slug, ''),
	       (SELECT COUNT(*) FROM audit_logs b WHERE b.batch_id = a.id)
	FROM audit_logs a
	LEFT JOIN users        au ON au.id = a.actor_user_id
	LEFT JOIN machines     am ON am.id = a.actor_machine_id
	LEFT JOIN users        tu ON tu.id = a.target_user_id
	LEFT JOIN machines     tm ON tm.id = a.target_machine_id
	LEFT JOIN environments te ON te.id = a.target_environment_id
	LEFT JOIN projects     tp ON tp.id = te.project_id`

// where は絞り込み条件を、SQL の条件式と引数に変換する。
//
// **条件式は固定の文字列だけで組み立てる。** 利用者の入力は全て引数(?)で渡す。
//
// 先頭は必ず `a.batch_id IS NULL` である。単独の行と batch の先頭行だけを拾い、
// batch の後続行は先頭行に畳む(AuditRow.Batch)。
func (f AuditFilter) where() (conds []string, args []any) {
	conds = []string{"a.batch_id IS NULL"}
	add := func(cond string, arg any) {
		conds = append(conds, cond)
		args = append(args, arg)
	}

	if f.From != nil {
		add("a.at >= ?", f.From.Unix())
	}
	if f.To != nil {
		add("a.at < ?", f.To.Unix())
	}
	switch {
	case f.ActorUserID != nil:
		add("a.actor_user_id = ?", *f.ActorUserID)
	case f.ActorMachineID != nil:
		add("a.actor_machine_id = ?", *f.ActorMachineID)
	case f.ActorAnonymous:
		conds = append(conds, "a.actor_user_id IS NULL AND a.actor_machine_id IS NULL")
	}
	if f.Action != "" {
		add("a.action = ?", string(f.Action))
	}
	if f.Result != "" {
		add("a.result = ?", string(f.Result))
	}
	if f.EnvironmentID != nil {
		add("a.target_environment_id = ?", *f.EnvironmentID)
	}
	return conds, args
}

// whereFrom は、絞り込み条件に「pos より古い側("<")/ 新しい側(">")」を足した
// 条件式と引数を返す。op は呼び出し側が書いた定数であり、入力は入らない。
//
// 並びは (at DESC, id DESC) で、idx_audit_head がその順に持っている
// (migrations/0002)。同じ秒の行は id で順序が決まるので、位置は 2 つの組で指す。
func (f AuditFilter) whereFrom(op string, pos AuditCursor) (string, []any) {
	conds, args := f.where()
	conds = append(conds, "(a.at, a.id) "+op+" (?, ?)")
	return strings.Join(conds, " AND "), append(args, pos.At, pos.ID)
}

// listSQL は 1 ページ分の問い合わせと引数を組み立てる。
//
// **進む方向の先にまだ行があるかを確かめるため、Limit より 1 行多く読む。**
// 新しい方へ進むとき(After)は古い順に読む(呼び出し側が並べ直す)。
func (q AuditQuery) listSQL() (string, []any) {
	var (
		where string
		args  []any
		order = "DESC"
	)
	switch {
	case q.After != nil:
		where, args = q.Filter.whereFrom(">", *q.After)
		order = "ASC"
	case q.Before != nil:
		where, args = q.Filter.whereFrom("<", *q.Before)
	default:
		conds, a := q.Filter.where()
		where, args = strings.Join(conds, " AND "), a
	}
	query := listAuditLogsSQL + " WHERE " + where +
		" ORDER BY a.at " + order + ", a.id " + order + " LIMIT ?"
	return query, append(args, q.Limit+1)
}

// ListAuditLogs は監査ログの 1 ページを、新しい順に返す。
//
// **削除機能は実装しない**(AGENTS.md ルール 28)。閲覧のみ。
//
// ページの位置は (at, id) で指す(keyset)。OFFSET で数えると、行が増え続ける
// 表では深いページほど遅くなり、読んでいる間に行が足されるとページがずれる。
func ListAuditLogs(ctx context.Context, db *sql.DB, q AuditQuery) (AuditPage, error) {
	query, args := q.listSQL()
	rows, err := queryAuditRows(ctx, db, query, args...)
	if err != nil {
		return AuditPage{}, err
	}

	more := len(rows) > q.Limit
	if more {
		rows = rows[:q.Limit]
	}
	if q.After != nil {
		// 新しい方へ進むときは古い順に読んでいる。表示は常に新しい順にする。
		slices.Reverse(rows)
	}
	page := AuditPage{Rows: rows}
	if len(rows) == 0 {
		return page, nil
	}
	if err := loadAuditBatches(ctx, db, rows, auditBatchInlineLimit); err != nil {
		return AuditPage{}, err
	}

	newest := &AuditCursor{At: rows[0].At.Unix(), ID: rows[0].ID}
	oldest := &AuditCursor{At: rows[len(rows)-1].At.Unix(), ID: rows[len(rows)-1].ID}

	// 進んできた方向の先は more で分かる。**逆の方向は問い合わせて確かめる**
	// (「戻る」リンクを、行が無いのに出さない)。最新のページには新しい側が無い。
	var hasOlder, hasNewer bool
	switch {
	case q.After != nil:
		hasNewer = more
		hasOlder, err = auditRowExists(ctx, db, q.Filter, "<", *oldest)
	case q.Before != nil:
		hasOlder = more
		hasNewer, err = auditRowExists(ctx, db, q.Filter, ">", *newest)
	default:
		hasOlder = more
	}
	if err != nil {
		return AuditPage{}, err
	}
	if hasOlder {
		page.Older = oldest
	}
	if hasNewer {
		page.Newer = newest
	}
	return page, nil
}

// queryAuditRows は listAuditLogsSQL の列を読み、表示用に解決する。
//
// query は AuditQuery.listSQL が、このファイルに書いた固定の断片(列、結合、
// 条件式、並び順)だけを繋いで作る。利用者の入力は全て args で渡る。条件に
// よって使う索引が変わるので、条件式を 1 つの固定の SQL に畳めない
// (`? IS NULL OR col = ?` の形にすると索引が使われない)。
func queryAuditRows(ctx context.Context, db *sql.DB, query string, args ...any) (_ []AuditRow, err error) {
	rows, err := db.QueryContext(ctx, query, args...) //nolint:gosec // G701: 上記のとおり、SQL の文面に入力は入らない
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list audit logs: %w", cerr)
		}
	}()

	var out []AuditRow
	for rows.Next() {
		var (
			a                               AuditRow
			at                              int64
			actorUserName, actorMachineName string
			target                          auditTargetRefs
			followers                       int
		)
		if err := rows.Scan(&a.ID, &at, &a.Action, &a.Result, &a.RemoteAddr, &a.Detail,
			&a.Actor, &actorUserName, &actorMachineName,
			&target.Stored, &target.UserID, &target.UserName,
			&target.MachineID, &target.MachineName,
			&target.ProjectSlug, &target.EnvSlug, &followers); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		a.At = time.Unix(at, 0).UTC()
		// 対象列で「実行者自身」を見分けるため、名前を付ける前の識別子を渡す。
		target.Actor = a.Actor
		// actor は user と machine のどちらか一方しか立たない(validate 済み)。
		switch {
		case actorUserName != "":
			a.Actor = auditSubject(a.Actor, actorUserName)
		case actorMachineName != "":
			a.Actor = auditSubject(a.Actor, actorMachineName)
		}
		// **key を対象にする行は、1 件だけでも batch と同じ形で出す。** 対象列には
		// 'project/env' を出し、key と detail(version 等)は畳んだ中に出す。
		// 単独の読み取りと bulk fetch で、画面の見え方を変えない。
		//
		// secret.* が記録する target は 'project/env/KEY' である。slug と key は
		// '/' を含まないので、最後の '/' より前が 'project/env' になる。
		// **記録時点の文字列から作る**(JOIN で引いた現在の slug は使わない。
		// 参照先が引けない行でも、どの環境かが読める)。
		// 拒否された読み取りは target を記録しないので、ここには入らない。
		keyRow := strings.HasPrefix(a.Action, "secret.") && strings.Contains(target.Stored, "/")
		if keyRow || followers > 0 {
			// 自分の key は Batch の 1 件目に入れる。後続行があれば
			// loadAuditBatches が足す。
			a.BatchSize = followers + 1
			a.Batch = []AuditBatchItem{{Target: target.Stored, Detail: a.Detail}}
			a.Detail = ""
			target.Stored = target.Stored[:max(strings.LastIndexByte(target.Stored, '/'), 0)]
		}
		a.Target = auditTarget(target)
		out = append(out, a)
	}
	return out, rows.Err()
}

// auditBatchInlineLimit は、一覧の中に畳んで出す batch の key の上限である。
//
// **1 ページの件数(auditPageSizes)は先頭行の数しか抑えない。** key が数百個
// ある environment の bulk fetch が並ぶと、後続行を全て読んで描画するだけで
// 1 ページが数万行になる。一覧にはここまでを出し、残りは batch の画面
// (ListAuditBatch)で全て見せる。**件数(BatchSize)は常に実数である。**
const auditBatchInlineLimit = 50

// loadAuditBatches は、rows の中の batch の先頭行に、後続行を足す。
//
// limit は 1 つの batch に載せる key の上限(先頭行を含む)で、0 以下なら全て
// 載せる。先頭行ごとに LIMIT 付きで引くので、読む行数は「先頭行の数 × limit」で
// 頭打ちになる(1 回でまとめて引くと、上限を超える分も読んでから捨てることになる)。
func loadAuditBatches(ctx context.Context, db *sql.DB, rows []AuditRow, limit int) (err error) {
	memberLimit := -1 // SQLite の LIMIT は負の数で無制限
	if limit > 0 {
		memberLimit = limit - 1
	}

	var stmt *sql.Stmt
	defer func() {
		if stmt != nil {
			if cerr := stmt.Close(); cerr != nil && err == nil {
				err = fmt.Errorf("list audit batch members: %w", cerr)
			}
		}
	}()

	for i := range rows {
		// 後続行があるのは 2 件以上の batch だけである(1 件は自分の key だけ)。
		if rows[i].BatchSize < 2 {
			continue
		}
		if stmt == nil {
			stmt, err = db.PrepareContext(ctx, `
				SELECT COALESCE(target, ''), COALESCE(detail, '')
				FROM audit_logs WHERE batch_id = ? ORDER BY id LIMIT ?`)
			if err != nil {
				return fmt.Errorf("list audit batch members: %w", err)
			}
		}
		if rows[i].Batch, err = appendAuditBatchItems(ctx, stmt, rows[i].Batch, rows[i].ID, memberLimit); err != nil {
			return err
		}
	}
	return nil
}

func appendAuditBatchItems(ctx context.Context, stmt *sql.Stmt, items []AuditBatchItem, headID int64, limit int) (_ []AuditBatchItem, err error) {
	members, err := stmt.QueryContext(ctx, headID, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit batch members: %w", err)
	}
	defer func() {
		if cerr := members.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list audit batch members: %w", cerr)
		}
	}()

	for members.Next() {
		var item AuditBatchItem
		if err := members.Scan(&item.Target, &item.Detail); err != nil {
			return nil, fmt.Errorf("scan audit batch member: %w", err)
		}
		items = append(items, item)
	}
	return items, members.Err()
}

// ListAuditBatch は、headID を先頭行とする batch を、key を省略せずに返す。
//
// 一覧は 1 つの batch の key を auditBatchInlineLimit 件までしか出さない。
// **どの key が読まれたかは監査の中身そのものなので、全てを見る手段を残す。**
// headID が batch の先頭行でなければ ErrNotFound を返す。
func ListAuditBatch(ctx context.Context, db *sql.DB, headID int64) (*AuditRow, error) {
	rows, err := queryAuditRows(ctx, db, listAuditLogsSQL+" WHERE a.id = ? AND a.batch_id IS NULL", headID)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || rows[0].BatchSize < 2 {
		return nil, ErrNotFound
	}
	if err := loadAuditBatches(ctx, db, rows, 0); err != nil {
		return nil, err
	}
	return &rows[0], nil
}

// auditRowExists は、絞り込み条件に合う行が pos より古い側("<")または新しい側
// (">")にあるかを返す。op は呼び出し側が書いた定数であり、入力は入らない。
func auditRowExists(ctx context.Context, db *sql.DB, f AuditFilter, op string, pos AuditCursor) (bool, error) {
	where, args := f.whereFrom(op, pos)
	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM audit_logs a WHERE `+where+`)`, args...).Scan(&exists); err != nil {
		return false, fmt.Errorf("probe audit logs: %w", err)
	}
	return exists, nil
}

// AuditEnvironment は、監査ログの「対象の環境」で選べる environment である。
type AuditEnvironment struct {
	EnvironmentID int64
	ProjectSlug   string
	EnvSlug       string
	// Deleted は environment か、その project が論理削除済みであることを示す。
	Deleted bool
}

// ListAuditEnvironments は、監査ログの絞り込みに使う environment を全て返す。
//
// **論理削除されたものも含める。** 監査は「その時点で何が起きたか」の記録で
// あり、削除した environment への過去のアクセスも調べられなければならない
// (ルール 58 は secret の取得経路の話で、ここには当たらない)。slug は再利用
// できるので、削除済みかどうかを併せて返す。
func ListAuditEnvironments(ctx context.Context, db *sql.DB) (_ []AuditEnvironment, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT e.id, p.slug, e.slug, (e.deleted_at IS NOT NULL OR p.deleted_at IS NOT NULL)
		FROM environments e
		JOIN projects p ON p.id = e.project_id
		ORDER BY p.slug, e.slug, e.id`)
	if err != nil {
		return nil, fmt.Errorf("list audit environments: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("list audit environments: %w", cerr)
		}
	}()

	var out []AuditEnvironment
	for rows.Next() {
		var e AuditEnvironment
		if err := rows.Scan(&e.EnvironmentID, &e.ProjectSlug, &e.EnvSlug, &e.Deleted); err != nil {
			return nil, fmt.Errorf("scan audit environment: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// auditSubject は監査行の主体 / 対象を 'name (user:1)' の形にする。
//
// **名前だけにしない。** machines.name に UNIQUE 制約は無いので名前は一意では
// なく、名前は後から変えられるが監査の追跡は immutable ID で行う(ルール 24)。
// 名前が引けないとき(#7 より前に作られた空名の machine 等)は識別子だけを返す。
func auditSubject(ident, name string) string {
	if name == "" {
		return ident
	}
	return name + " (" + ident + ")"
}

// auditTargetRefs は監査行の対象を指す列をまとめたものである。
type auditTargetRefs struct {
	Actor       string // 実行者の識別子('user:1' | 'machine:3' | 'anonymous')
	Stored      string // target 列(記録時点の表示文字列)
	UserID      sql.NullInt64
	UserName    string
	MachineID   sql.NullInt64
	MachineName string
	ProjectSlug string
	EnvSlug     string
}

// auditTarget は対象列の表示文字列を組み立てる。
//
// machine.* / user.* は target 列を持たず ID しか記録しないため、ここで解決
// しないと画面上は空欄になる。grant.* は「どの machine に、どの environment を」
// で 1 つの対象なので ' → ' で繋ぐ。
//
// **実行者自身は、ほかに出すものがあれば繰り返さない。** machine の secret.read
// は target_machine_id に自分を記録するので、そのまま出すと実行者列と同じ名前が
// 対象列にも並び('web01 (machine:3) → myapp/prod')、どこを読んだのかが
// 埋もれる。対象が実行者自身だけの行(自分のログイン、自分のパスワード変更)は
// 残す。空欄にすると「対象なし」と区別できない。
func auditTarget(t auditTargetRefs) string {
	var rest string
	switch {
	case t.Stored != "":
		// **記録時点の文字列を優先する。** item の key のように、ID からは
		// 引き直せない情報が入っている(item は論理削除しても行が残るが、
		// target 列は「その時どう見えていたか」を保つ)。
		rest = t.Stored
	case t.ProjectSlug != "" && t.EnvSlug != "":
		// grant.delete は target 列を持たず environment_id だけを記録する。
		rest = t.ProjectSlug + "/" + t.EnvSlug
	}

	var parts []string
	subject := func(ident, name string) {
		if rest != "" && ident == t.Actor {
			return
		}
		parts = append(parts, auditSubject(ident, name))
	}
	if t.MachineID.Valid {
		subject(actorMachine(t.MachineID.Int64), t.MachineName)
	}
	if t.UserID.Valid {
		subject(actorUser(t.UserID.Int64), t.UserName)
	}
	if rest != "" {
		parts = append(parts, rest)
	}
	return strings.Join(parts, " → ")
}
