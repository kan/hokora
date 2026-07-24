package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// secretRef は「どの secret か」を表示用文字列と immutable ID の両方で持つ。
//
// slug / key は再利用できるので、監査ログには **両方** を記録する
// (THREAT_MODEL §10.2)。
type secretRef struct {
	Env    *EnvironmentRef
	ItemID int64
	Key    string
}

func (r secretRef) target() string {
	return r.Env.ProjectSlug + "/" + r.Env.EnvSlug + "/" + r.Key
}

// auditEntry は secret 操作の監査行を組み立てる。**対象の ID を必ず埋める。**
func (r secretRef) auditEntry(ac auditCtx, action Action, result Result, version int) AuditEntry {
	target := r.target()
	entry := ac.entry(action, result, &AuditDetail{Version: &version})
	entry.Target = &target
	entry.TargetProjectID = &r.Env.ProjectID
	entry.TargetEnvironmentID = &r.Env.EnvironmentID
	if r.ItemID != 0 {
		entry.TargetItemID = &r.ItemID
	}
	return entry
}

// PutSecret は secret を作成または更新する。
//
// **item_versions は追記のみ**(AGENTS.md ルール 55)。更新は新しい version を
// 足し、items.current_version を進めることで行う。過去の版は書き換えない。
//
// **監査は fail closed**(THREAT_MODEL §10.4)。記録できなければ書き込みも
// 確定させない。
//
// 暗号化は Vault の read lock 内で完結させる(C1)。DEK を fn の外へ持ち出さない。
//
// **ロック獲得順序: Vault.mu(read) → SQLite 書き込みロック**(C7 の拡張)。
// WithDEK で read lock を取ってから withTx を開く。逆順(DB tx を開いてから
// Vault ロックを取る)にすると、Vault の write lock を保持する revoke 系
// (machine.disable / rotate_secret)と順序が逆転し、新規 key の書き込みと
// 緊急遮断が SQLITE_BUSY で衝突しうる。**DB tx を開いている間に Vault の
// ロックを取らない。**
func PutSecret(ctx context.Context, v *Vault, env *EnvironmentRef, key string, value []byte, ac auditCtx) error {
	if err := ValidateItemKey(key); err != nil {
		return err
	}
	// **サーバー側で検証する**(DESIGN §5.3)。有効な UTF-8、NUL なし、64 KB 以下。
	if err := ValidateSecretValue(value); err != nil {
		return err
	}

	// 先に read lock を取る。sealed なら withTx を開く前に ErrSealed で戻る。
	return v.WithDEK(func(dek []byte, dekVersion int64) error {
		return withTx(ctx, v.db, func(tx *sql.Tx) error {
			itemID, version, err := nextItemVersion(ctx, tx, env.EnvironmentID, key, ac.Now)
			if err != nil {
				return err
			}

			aad, err := itemAAD(itemID, version, dekVersion)
			if err != nil {
				return err
			}
			ciphertext, nonce, err := sealBytes(dek, value, aad)
			if err != nil {
				return err
			}

			if _, err := tx.ExecContext(ctx, `
				INSERT INTO item_versions (item_id, version, value_enc, nonce, dek_version, created_at, created_by)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				itemID, version, ciphertext, nonce, dekVersion, ac.Now.Unix(), ac.Actor); err != nil {
				return fmt.Errorf("insert item version: %w", err)
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE items SET current_version = ?, updated_at = ? WHERE id = ?`,
				version, ac.Now.Unix(), itemID); err != nil {
				return fmt.Errorf("update item: %w", err)
			}

			ref := secretRef{Env: env, ItemID: itemID, Key: key}
			return RecordAudit(ctx, tx, ref.auditEntry(ac, ActionSecretWrite, ResultSuccess, int(version)))
		})
	})
}

// nextItemVersion は item を用意し、次の version 番号を返す。
//
// 既存の item が無ければ作る。**論理削除済みの key は再利用できる**
// (部分 UNIQUE インデックス)。その場合は新しい行になる。
func nextItemVersion(ctx context.Context, tx *sql.Tx, environmentID int64, key string, now time.Time) (itemID, version int64, err error) {
	var current int64
	err = tx.QueryRowContext(ctx, `
		SELECT id, current_version FROM items
		WHERE environment_id = ? AND key = ? AND deleted_at IS NULL`,
		environmentID, key).Scan(&itemID, &current)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `
			INSERT INTO items (environment_id, key, current_version, created_at, updated_at)
			VALUES (?, ?, 0, ?, ?)`, environmentID, key, now.Unix(), now.Unix())
		if err != nil {
			return 0, 0, fmt.Errorf("insert item: %w", err)
		}
		if itemID, err = res.LastInsertId(); err != nil {
			return 0, 0, fmt.Errorf("insert item: %w", err)
		}
		return itemID, 1, nil
	case err != nil:
		return 0, 0, fmt.Errorf("find item: %w", err)
	default:
		return itemID, current + 1, nil
	}
}

// RevealSecret は平文を返す。
//
// **監査ログの記録が成功してから平文をレスポンスに含める**(DESIGN §9.1)。
// この関数が値を返した時点で、監査は確定している。
//
// version が 0 なら現行版、それ以外は指定版(履歴からの表示)。
func RevealSecret(ctx context.Context, v *Vault, env *EnvironmentRef, key string, version int64, ac auditCtx) (string, error) {
	item, err := FindItem(ctx, v.db, env.EnvironmentID, key)
	if err != nil {
		return "", err
	}
	if version == 0 {
		version = item.CurrentVersion
	}

	enc, err := GetItemVersion(ctx, v.db, item.ID, version)
	if err != nil {
		return "", err
	}

	var plaintext []byte
	if err := v.WithDEK(func(dek []byte, dekVersion int64) error {
		var err error
		plaintext, err = decryptSecret(dek, dekVersion, *enc)
		return err
	}); err != nil {
		return "", err
	}
	defer Zero(plaintext)

	// **記録してから返す。** ここが失敗したら平文は返さない(fail closed)。
	ref := secretRef{Env: env, ItemID: item.ID, Key: key}
	if err := RecordAudit(ctx, v.db, ref.auditEntry(ac, ActionSecretReveal, ResultSuccess, int(version))); err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// DeleteItem は item を論理削除する。
//
// **物理削除しない**(AGENTS.md ルール 56)。過去の版も残るため、監査ログの
// item_id は引き続き解決できる。
//
// 監査は fail closed(secret の削除は「セキュリティを下げる操作」ではないが、
// THREAT_MODEL §10.4 の表で fail closed に分類されている)。
func DeleteItem(ctx context.Context, db *sql.DB, env *EnvironmentRef, key string, ac auditCtx) error {
	return withTx(ctx, db, func(tx *sql.Tx) error {
		item, err := FindItem(ctx, tx, env.EnvironmentID, key)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE items SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
			ac.Now.Unix(), ac.Now.Unix(), item.ID)
		if err != nil {
			return fmt.Errorf("delete item: %w", err)
		}
		if err := requireOneRow(res, "item"); err != nil {
			return err
		}

		ref := secretRef{Env: env, ItemID: item.ID, Key: key}
		return RecordAudit(ctx, tx, ref.auditEntry(ac, ActionSecretDelete, ResultSuccess, int(item.CurrentVersion)))
	})
}

// ---- project / environment ----

// CreateProject は project を作る。監査は fail closed。
func CreateProject(ctx context.Context, db *sql.DB, slug, name string, ac auditCtx) (id int64, err error) {
	if err := ValidateSlug(slug); err != nil {
		return 0, err
	}
	if name == "" {
		name = slug
	}

	err = withTx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO projects (slug, name, created_at, updated_at) VALUES (?, ?, ?, ?)`,
			slug, name, ac.Now.Unix(), ac.Now.Unix())
		if err != nil {
			return fmt.Errorf("insert project: %w", err)
		}
		if id, err = res.LastInsertId(); err != nil {
			return fmt.Errorf("insert project: %w", err)
		}

		entry := ac.entry(ActionProjectCreate, ResultSuccess, nil)
		entry.Target = &slug
		entry.TargetProjectID = &id
		return RecordAudit(ctx, tx, entry)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// DeleteProject は project を論理削除する。
//
// **配下の environment / item は残る。** 取得側が全祖先の deleted_at を検査
// するので、これで配下ごと見えなくなる(THREAT_MODEL §11.1)。物理削除に
// しないのは、監査ログの target_project_id を解決可能に保つためである。
func DeleteProject(ctx context.Context, db *sql.DB, slug string, ac auditCtx) error {
	return withTx(ctx, db, func(tx *sql.Tx) error {
		p, err := FindProject(ctx, tx, slug)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE projects SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
			ac.Now.Unix(), ac.Now.Unix(), p.ID)
		if err != nil {
			return fmt.Errorf("delete project: %w", err)
		}
		if err := requireOneRow(res, "project"); err != nil {
			return err
		}

		entry := ac.entry(ActionProjectDelete, ResultSuccess, nil)
		entry.Target = &slug
		entry.TargetProjectID = &p.ID
		return RecordAudit(ctx, tx, entry)
	})
}

// CreateEnvironment は environment を作る。監査は fail closed。
func CreateEnvironment(ctx context.Context, db *sql.DB, projectSlug, slug, name string, ac auditCtx) (id int64, err error) {
	if err := ValidateSlug(slug); err != nil {
		return 0, err
	}
	if name == "" {
		name = slug
	}

	err = withTx(ctx, db, func(tx *sql.Tx) error {
		p, err := FindProject(ctx, tx, projectSlug)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO environments (project_id, slug, name, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)`, p.ID, slug, name, ac.Now.Unix(), ac.Now.Unix())
		if err != nil {
			return fmt.Errorf("insert environment: %w", err)
		}
		if id, err = res.LastInsertId(); err != nil {
			return fmt.Errorf("insert environment: %w", err)
		}

		target := projectSlug + "/" + slug
		entry := ac.entry(ActionEnvironmentCreate, ResultSuccess, nil)
		entry.Target = &target
		entry.TargetProjectID = &p.ID
		entry.TargetEnvironmentID = &id
		return RecordAudit(ctx, tx, entry)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// DeleteEnvironment は environment を論理削除する。
func DeleteEnvironment(ctx context.Context, db *sql.DB, projectSlug, envSlug string, ac auditCtx) error {
	return withTx(ctx, db, func(tx *sql.Tx) error {
		env, err := ResolveEnvironment(ctx, tx, projectSlug, envSlug)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE environments SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
			ac.Now.Unix(), ac.Now.Unix(), env.EnvironmentID)
		if err != nil {
			return fmt.Errorf("delete environment: %w", err)
		}
		if err := requireOneRow(res, "environment"); err != nil {
			return err
		}

		target := projectSlug + "/" + envSlug
		entry := ac.entry(ActionEnvironmentDelete, ResultSuccess, nil)
		entry.Target = &target
		entry.TargetProjectID = &env.ProjectID
		entry.TargetEnvironmentID = &env.EnvironmentID
		return RecordAudit(ctx, tx, entry)
	})
}

// ---- grant ----

// CreateGrant は machine に environment への grant を与える。監査は fail closed。
//
// environment は **ID で受け取る**(UI のプルダウンは environment_id を送る)。
// FindEnvironmentByID が祖先の deleted_at を検査するので、論理削除済みや
// 存在しない ID は弾かれる。
func CreateGrant(ctx context.Context, db *sql.DB, machineID, environmentID int64, ac auditCtx) error {
	return withTx(ctx, db, func(tx *sql.Tx) error {
		return insertGrantTx(ctx, tx, machineID, environmentID, ac)
	})
}

// insertGrantTx は grant 行を追記し、作成の監査を記録する。fail closed。
//
// **CreateGrant と CreateMachineWithGrant(#9)で共通の tx 本体である。**
// FindEnvironmentByID が祖先の deleted_at を検査するので、論理削除済みや
// 存在しない ID は弾かれる(ルール54/58)。
func insertGrantTx(ctx context.Context, tx *sql.Tx, machineID, environmentID int64, ac auditCtx) error {
	env, err := FindEnvironmentByID(ctx, tx, environmentID)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO machine_grants (machine_id, environment_id, created_at) VALUES (?, ?, ?)`,
		machineID, env.EnvironmentID, ac.Now.Unix()); err != nil {
		return fmt.Errorf("insert grant: %w", err)
	}

	target := env.ProjectSlug + "/" + env.EnvSlug
	entry := ac.entry(ActionGrantCreate, ResultSuccess, nil)
	entry.Target = &target
	entry.TargetProjectID = &env.ProjectID
	entry.TargetEnvironmentID = &env.EnvironmentID
	entry.TargetMachineID = &machineID
	return RecordAudit(ctx, tx, entry)
}

// DeleteGrant は grant を削除する。
//
// **grant は物理削除を許可する**(AGENTS.md ルール 56 の例外)。削除は次の
// リクエストの再検査で即座に効く(DESIGN §4.5)ので、トークンの失効は要らない。
//
// **監査は fail open**(緊急遮断操作である。THREAT_MODEL §10.4)。
func DeleteGrant(ctx context.Context, db *sql.DB, logger *slog.Logger, machineID, environmentID int64, ac auditCtx) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM machine_grants WHERE machine_id = ? AND environment_id = ?`,
		machineID, environmentID)
	if err != nil {
		return fmt.Errorf("delete grant: %w", err)
	}
	if err := requireOneRow(res, "grant"); err != nil {
		return err
	}

	entry := ac.entry(ActionGrantDelete, ResultSuccess, nil)
	entry.TargetEnvironmentID = &environmentID
	entry.TargetMachineID = &machineID
	RecordAuditBestEffort(ctx, db, logger, entry)
	return nil
}
