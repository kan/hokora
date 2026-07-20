package main

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
)

//go:embed schema.sql
var schemaSQL string

// schemaVersion は本バイナリが期待するスキーマのバージョンである。
// PRAGMA user_version に記録する。MVP は単一スキーマなので schema_version
// テーブルを作るまでもない(DESIGN §3.1)。
const schemaVersion = 1

// schemaVersionOf は DB に記録されたスキーマバージョンを返す。
// 未初期化の DB では 0 を返す。
func schemaVersionOf(ctx context.Context, db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, fmt.Errorf("read user_version: %w", err)
	}
	return version, nil
}

// Migrate はスキーマを現行バージョンまで適用する。適用済みなら何もしない。
//
// バージョンが一致も 0 でもない DB は拒否する。古いバイナリで新しい DB を
// 開くと、知らないカラムを無視したまま書き込みかねない。将来バージョンが
// 増えたら、ここに 0 以外からの移行経路を足す。
func Migrate(ctx context.Context, db *sql.DB) error {
	current, err := schemaVersionOf(ctx, db)
	if err != nil {
		return err
	}
	if current == schemaVersion {
		return nil
	}
	if current != 0 {
		return fmt.Errorf("no migration path from database schema version %d to %d", current, schemaVersion)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit 済みなら no-op

	if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	// PRAGMA はプレースホルダを受け付けないが、schemaVersion は定数なので
	// 外部入力は混入しない。
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}
