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
