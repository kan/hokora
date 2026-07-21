package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
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

// openDatabase は接続だけを確立し、スキーマのバージョンを検査しない。
// スキーマ未適用の DB を扱ってよいのは init(Migrate)だけなので、直接呼ぶのは
// init と OpenStore に限る。他の経路は必ず OpenStore を通す。
func openDatabase(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", dataSourceName(path))
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
type AuditRow struct {
	At         time.Time
	Actor      string
	Action     string
	Target     string
	Result     string
	RemoteAddr string
	Detail     string
}

// ListAuditLogs は監査ログを新しい順に返す。
//
// **削除機能は実装しない**(AGENTS.md ルール 28)。閲覧のみ。
func ListAuditLogs(ctx context.Context, db *sql.DB, limit int) (_ []AuditRow, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT at, actor, action, COALESCE(target, ''), result,
		       COALESCE(remote_addr, ''), COALESCE(detail, '')
		FROM audit_logs ORDER BY at DESC, id DESC LIMIT ?`, limit)
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
			a  AuditRow
			at int64
		)
		if err := rows.Scan(&at, &a.Actor, &a.Action, &a.Target, &a.Result, &a.RemoteAddr, &a.Detail); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}
		a.At = time.Unix(at, 0).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}
