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
