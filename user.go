package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"
)

// usernamePattern は username の文字種である。
//
// 表示にも監査ログの actor 組み立てにも使うため、制御文字や空白を許さない。
// actor には ID しか入らない(DESIGN §5.5)が、入力の段階で狭めておく。
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrInvalidUsername は username の形式が不正であることを示す。
var ErrInvalidUsername = errors.New("invalid username")

// ValidateUsername は username を検証する。
func ValidateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	return nil
}

// LoginResult はログインの成果である。
type LoginResult struct {
	UserID       int64
	Username     string
	MustChangePW bool
	// Token は Cookie に設定する生のセッショントークンである。
	Token string
}

// Login はパスワードを検証し、新しいセッションを作る。
//
// **C9(DESIGN §4.4):** argon2 の検証には数百 ms かかる。その間にパスワードが
// 変更されると、次の並びで旧パスワード由来のセッションが生き残る:
//
//	login:  旧 password_hash を読み、argon2 検証(数百 ms)
//	change: hash 更新 + 全 session DELETE + 監査を tx で commit
//	login:  新 session を INSERT           ← 削除をすり抜けた
//
// **対策は「セッション INSERT と同一トランザクション内で password_hash を
// 再読し、検証に使った値と一致することを確認する」ことである。** 変更側は
// 「hash 更新 + sessions DELETE + 監査」が既に 1 tx なので、SQLite の
// 直列化で決着する。ロックを増やさずに済む。
//
// **セッション ID は常に新規生成される**(AGENTS.md ルール 45)。既存の
// セッションを再利用しないので、session fixation は成立しない。
//
// **監査は fail closed**(THREAT_MODEL §10.4)。成功・失敗とも、記録できな
// ければ認証を通さない。
func Login(ctx context.Context, db *sql.DB, username, password, remoteAddr string, now time.Time) (*LoginResult, error) {
	// 手順 1: password_hash を読む(tx 外)。
	var (
		userID       int64
		storedHash   string
		mustChange   int
		disabled     int
		userExists   = true
		auditFailure = func() error {
			digest := subjectDigest(username)
			reason := ReasonInvalidCredentials
			ac := anonymousAudit(remoteAddr, now)
			return RecordAudit(ctx, db, ac.entry(ActionAuthUser, ResultFailure, &AuditDetail{
				Reason:        &reason,
				SubjectDigest: &digest,
			}))
		}
	)

	err := db.QueryRowContext(ctx,
		`SELECT id, password_hash, must_change_pw, disabled FROM users WHERE username = ?`, username,
	).Scan(&userID, &storedHash, &mustChange, &disabled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		userExists = false
	case err != nil:
		return nil, fmt.Errorf("find user: %w", err)
	}

	// 手順 2: argon2 で検証(tx 外。数百 ms)。
	//
	// **存在しない username でも必ず argon2 を実行する**(DESIGN §7.2)。
	// 早期 return すると、応答時間の差で username の存在が分かる。
	verifyHash := storedHash
	if !userExists {
		dummy, err := dummyPasswordHash()
		if err != nil {
			return nil, err
		}
		verifyHash = dummy
	}
	ok, err := VerifyPassword(ctx, verifyHash, password)
	if err != nil && !errors.Is(err, ErrPasswordTooLong) {
		// 壊れたハッシュ等。認証は通さない。
		return nil, err
	}

	if !userExists || !ok || disabled != 0 {
		if auditErr := auditFailure(); auditErr != nil {
			return nil, auditErr
		}
		return nil, ErrInvalidCredentials
	}

	raw, encoded, err := GenerateSessionToken()
	if err != nil {
		return nil, err
	}
	defer Zero(raw)

	// 手順 3〜6: 再読・確認・INSERT・監査を 1 トランザクションで。
	err = withTx(ctx, db, func(tx *sql.Tx) error {
		var current string
		if err := tx.QueryRowContext(ctx,
			`SELECT password_hash FROM users WHERE id = ? AND disabled = 0`, userID).Scan(&current); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// 検証中に無効化された。
				return ErrInvalidCredentials
			}
			return fmt.Errorf("re-read password hash: %w", err)
		}
		// **検証に使った値と一致するか確認する**(C9)。
		// 一致しなければ、その間にパスワードが変更されている。
		if !constantTimeEqual([]byte(current), []byte(storedHash)) {
			return ErrInvalidCredentials
		}

		if err := createSession(ctx, tx, userID, raw, remoteAddr, now); err != nil {
			return err
		}

		ac := userAudit(userID, remoteAddr, now)
		return RecordAudit(ctx, tx, ac.userEntry(ActionAuthUser, userID))
	})
	if errors.Is(err, ErrInvalidCredentials) {
		if auditErr := auditFailure(); auditErr != nil {
			return nil, auditErr
		}
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		UserID:       userID,
		Username:     username,
		MustChangePW: mustChange != 0,
		Token:        encoded,
	}, nil
}

// Logout はセッションを削除する。
//
// **監査は fail open**(セキュリティを上げる操作である。THREAT_MODEL §10.4)。
func Logout(ctx context.Context, db *sql.DB, logger *slog.Logger, userID int64, raw []byte, ac auditCtx) error {
	if err := DeleteSession(ctx, db, raw); err != nil {
		return err
	}
	// target_user_id を入れて user.* の他の action と揃える。actor と同じ値に
	// なるが、「誰のセッションが消えたか」で検索できる形にしておく。
	RecordAuditBestEffort(ctx, db, logger, ac.userEntry(ActionLogout, userID))
	return nil
}

// CreateUser はユーザーを作る。
//
// **初期パスワードは呼び出し側が生成して一度だけ表示する。** 保存されるのは
// argon2id のハッシュだけなので、後から取り出せない。
//
// 監査は fail closed(作成はセキュリティを下げる方向の操作である)。
func CreateUser(ctx context.Context, db *sql.DB, username, password string, mustChangePW bool, ac auditCtx) (id int64, err error) {
	if err := ValidateUsername(username); err != nil {
		return 0, err
	}
	hash, err := HashPassword(ctx, password)
	if err != nil {
		return 0, err
	}

	mustChange := 0
	if mustChangePW {
		mustChange = 1
	}

	err = withTx(ctx, db, func(tx *sql.Tx) error {
		at := ac.Now.Unix()
		res, err := tx.ExecContext(ctx, `
			INSERT INTO users (username, password_hash, must_change_pw, disabled, created_at, updated_at)
			VALUES (?, ?, ?, 0, ?, ?)`, username, hash, mustChange, at, at)
		if err != nil {
			return fmt.Errorf("insert user: %w", err)
		}
		if id, err = res.LastInsertId(); err != nil {
			return fmt.Errorf("insert user: %w", err)
		}

		return RecordAudit(ctx, tx, ac.userEntry(ActionUserCreate, id))
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// DisableUser はユーザーを無効化し、そのセッションを全て削除する。
//
// **監査は fail open**(緊急遮断操作。THREAT_MODEL §10.4)。本体(無効化と
// セッション削除)の失敗はエラーとして返す。
//
// セッション削除と DB 更新を 1 トランザクションにまとめるのは、
// 「無効化されたのにセッションが残る」状態を作らないためである。
// なお LookupSession が毎回 disabled を読むので、削除が漏れても素通りは
// しない(多層防御)。
func DisableUser(ctx context.Context, db *sql.DB, logger *slog.Logger, userID int64, ac auditCtx) error {
	err := withTx(ctx, db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE users SET disabled = 1, updated_at = ? WHERE id = ?`, ac.Now.Unix(), userID)
		if err != nil {
			return fmt.Errorf("disable user: %w", err)
		}
		if err := requireOneRow(res, "user"); err != nil {
			return err
		}
		return deleteSessionsByUser(ctx, tx, userID)
	})
	if err != nil {
		return err
	}

	RecordAuditBestEffort(ctx, db, logger, ac.userEntry(ActionUserDisable, userID))
	return nil
}

// ChangePassword はパスワードを変更し、当該ユーザーの全セッションを削除する。
//
// **sealed 状態でも動作しなければならない**(DESIGN §8.3)。初回セットアップ
// 時は必ず sealed であり、ここで DEK を要求すると初回ログインが詰む。
// パスワードは DEK ではなく argon2id で守られるので、依存しない。
//
// **C9 の相手側である。** hash 更新・セッション削除・監査を 1 トランザクション
// にまとめることで、ログイン側の再読検証と SQLite の直列化により決着する。
//
// **監査は fail open**(漏洩対応の緊急操作でもある。THREAT_MODEL §10.4)。
//
// 呼び出し側は、戻り値のトークンで Cookie を張り直す(全セッションを消すので、
// 実行者自身のセッションも消えている。これがセッション再生成でもある)。
func ChangePassword(ctx context.Context, db *sql.DB, logger *slog.Logger, userID int64, current, next string, ac auditCtx) (token string, err error) {
	var stored string
	if err := db.QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE id = ? AND disabled = 0`, userID).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("find user: %w", err)
	}

	ok, err := VerifyPassword(ctx, stored, current)
	if err != nil && !errors.Is(err, ErrPasswordTooLong) {
		return "", err
	}
	if !ok {
		return "", ErrInvalidCredentials
	}
	// 同じパスワードへの「変更」を許すと、変更を強制した意味が無くなる。
	if current == next {
		return "", errors.New("the new password must differ from the current one")
	}

	hash, err := HashPassword(ctx, next)
	if err != nil {
		return "", err
	}

	raw, encoded, err := GenerateSessionToken()
	if err != nil {
		return "", err
	}
	defer Zero(raw)

	err = withTx(ctx, db, func(tx *sql.Tx) error {
		// **UPDATE の条件に disabled = 0 を含める。**
		//
		// 事前の SELECT では disabled を見ているが、そこから argon2(数百 ms)
		// を挟むため、その間に無効化が確定しうる。C9 と同型の競合であり、
		// 条件に含めないと「無効化済みユーザーのパスワードが書き換わり、
		// must_change_pw まで下りる」状態を作れる。
		// (AGENTS.md の教訓「競合を 1 つ見つけたら、同じ構造が他にないか探す」)
		res, err := tx.ExecContext(ctx, `
			UPDATE users SET password_hash = ?, must_change_pw = 0, updated_at = ?
			WHERE id = ? AND password_hash = ? AND disabled = 0`, hash, ac.Now.Unix(), userID, stored)
		if err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		// **検証に使ったハッシュが変わっていたら中止する。** 並行して別の
		// 変更が確定した場合、こちらを上書きしない。無効化された場合も
		// ここで 0 行になり、中止される。
		if err := requireOneRow(res, "user"); err != nil {
			return err
		}

		// **当該ユーザーの全セッションを削除する**(AGENTS.md ルール 53)。
		if err := deleteSessionsByUser(ctx, tx, userID); err != nil {
			return err
		}
		// 実行者自身は締め出さない。新しいセッションを同じ tx で作る
		// (= セッション ID の再生成)。
		return createSession(ctx, tx, userID, raw, ac.remoteAddr(), ac.Now)
	})
	if err != nil {
		return "", err
	}

	RecordAuditBestEffort(ctx, db, logger, ac.userEntry(ActionUserPasswordChange, userID))
	return encoded, nil
}

// userAudit は user が actor である監査コンテキストを作る。
func userAudit(userID int64, remoteAddr string, now time.Time) auditCtx {
	return auditCtx{
		Actor:       actorUser(userID),
		ActorUserID: &userID,
		Via:         ViaWeb,
		RemoteAddr:  &remoteAddr,
		Now:         now,
	}
}
