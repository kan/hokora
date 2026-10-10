package main

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
)

//go:embed schema.sql
var schemaSQL string

//go:embed migrations/0002_audit_batch.sql
var migration0002SQL string

// migrations は、スキーマを 1 つ進める SQL を順に並べたものである。
// migrations[i] はバージョン i の DB を i+1 にする。
//
// **新規の DB も、既存の DB と同じ手順を先頭から踏む。** 「新規用の完成形
// スキーマ」と「移行用の差分」を別々に持つと、片方だけ直して両者がずれる
// (新規では通るのに、移行した本番 DB では列やインデックスが無い)。経路を
// 1 本にして、ずれる余地を無くす。
//
// **適用済みの SQL は書き換えない。** 変更は新しい要素を末尾に足して行う。
// schema.sql は v1 の内容であり、現在の完成形ではない。
//
// 並びが migrations/ のファイル名の番号順と一致していること、ファイルを足して
// ここへの追加を忘れていないことは、TestMigrationsMatchTheFiles が確かめる。
//
// 配列にしてあるのは、schemaVersion を定数にするためである(スライスの len は
// 定数にならない)。
var migrations = [...]string{
	schemaSQL,        // 0 → 1
	migration0002SQL, // 1 → 2: audit_logs.batch_id と環境の絞り込み用インデックス
}

// schemaVersion は本バイナリが期待するスキーマのバージョンである。
// PRAGMA user_version に記録する。直線的な移行しか無いので schema_version
// テーブルを作るまでもない(DESIGN §3.1)。
//
// **定数である。** OpenStore が全ての DB を開くときの関門なので、実行中に
// 書き換えられる変数にしない。
const schemaVersion = len(migrations)

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
// **バイナリより新しい DB は拒否する。** 古いバイナリで新しい DB を開くと、
// 知らないカラムを無視したまま書き込みかねない。
//
// 未適用の移行は **1 つのトランザクションで全て適用する**。途中で失敗したら
// 全て巻き戻り、user_version も元のままになる(中途半端なバージョンの DB を
// 残さない)。
func Migrate(ctx context.Context, db *sql.DB) error {
	return migrate(ctx, db, migrations[:])
}

// migrate は steps の末尾まで DB を進める。steps[i] はバージョン i を i+1 にする。
//
// 手順を引数で受けるのは、テストが「v1 で止めた DB」や「途中で失敗する移行」を、
// パッケージ変数を書き換えずに作れるようにするためである。
func migrate(ctx context.Context, db *sql.DB, steps []string) error {
	target := len(steps)
	current, err := schemaVersionOf(ctx, db)
	if err != nil {
		return err
	}
	if current == target {
		return nil
	}
	if current < 0 || current > target {
		return fmt.Errorf("no migration path from database schema version %d to %d", current, target)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // commit 済みなら no-op

	for v := current; v < target; v++ {
		if _, err := tx.ExecContext(ctx, steps[v]); err != nil {
			applyErr := fmt.Errorf("apply schema migration %d -> %d: %w", v, v+1, err)
			// バージョンはトランザクションの外で読んでいるので、**同時に走った
			// 別の `hokora init` が先に移行を終えている**ことがある。その場合
			// こちらは「列が既にある」等で失敗するが、DB は正しく移行済みである。
			// 巻き戻してから読み直し、目標に達していれば成功として扱う。
			if rbErr := tx.Rollback(); rbErr != nil {
				return errors.Join(applyErr, rbErr)
			}
			if now, verr := schemaVersionOf(ctx, db); verr == nil && now == target {
				return nil
			}
			return applyErr
		}
	}
	// PRAGMA はプレースホルダを受け付けないが、target は手順の数から決まる整数
	// なので外部入力は混入しない。
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", target)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}
