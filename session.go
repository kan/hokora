package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// セッションの仕様(DESIGN §7.2)。
const (
	// SessionTokenBytes はセッショントークンの長さである。
	SessionTokenBytes = 32
	// SessionAbsoluteTTL は絶対期限である。
	SessionAbsoluteTTL = 12 * time.Hour
	// SessionIdleTTL は idle 期限である。
	SessionIdleTTL = 2 * time.Hour

	// SessionCookieName は __Host- prefix 付きの Cookie 名である。
	//
	// **`__Host-` prefix は、Domain 属性なし・Path=/・Secure をブラウザ側で
	// 強制する**(AGENTS.md ルール 44)。サブドメインから上書きされる経路を
	// 閉じるため、名前自体で担保する。
	SessionCookieName = "__Host-hokora_session"
)

var (
	// ErrNoSession はセッションが無い、または無効であることを示す。
	//
	// **期限切れ・削除済み・ユーザー無効化を区別しない。** 区別しても
	// 利用者にできることは「ログインし直す」だけであり、区別は情報になる。
	ErrNoSession = errors.New("no valid session")

	// ErrInvalidCSRF は CSRF トークンが一致しないことを示す。
	ErrInvalidCSRF = errors.New("invalid csrf token")

	// ErrCrossOrigin は Fetch Metadata / Origin の検証に失敗したことを示す。
	ErrCrossOrigin = errors.New("cross-origin request rejected")
)

// SessionUser は認証済みのリクエストに紐づくユーザーである。
type SessionUser struct {
	UserID       int64
	Username     string
	MustChangePW bool
	// CSRFToken はこのリクエストで有効な CSRF トークンである。
	// セッショントークンから導出され、DB には保存されない。
	CSRFToken string
	// ExpiresAt / LastSeenAt は観測用(画面には出さない)。
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

// GenerateSessionToken は新しいセッショントークンを生成する。
func GenerateSessionToken() (raw []byte, encoded string, err error) {
	return generateRandomToken(SessionTokenBytes)
}

// DecodeSessionToken は Cookie の値を生バイト列へ戻す。
//
// 形式が不正なものは「セッションが無い」と同じに潰す。Cookie は利用者が
// 自由に書ける値なので、形式の違いを区別しても意味がない。
func DecodeSessionToken(encoded string) ([]byte, error) {
	raw, ok := decodeFixedLengthToken(encoded, SessionTokenBytes)
	if !ok {
		return nil, ErrNoSession
	}
	return raw, nil
}

// hashSessionToken はセッショントークンの保存表現を返す。
//
// **セッショントークンは SHA-256 ハッシュで DB 保存する**
// (AGENTS.md ルール 46)。bearer credential を平文で持たない。
func hashSessionToken(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// csrfToken はセッショントークンから CSRF トークンを導出する(DESIGN §7.3)。
//
// **DB に保存しない**(AGENTS.md ルール 47)。ハッシュ保存する設計は、
// フォーム描画時に埋め込む生値が存在しないため実装できない。
//
// 導出方式の性質:
//   - DB 漏洩から raw session を復元できない(SHA-256 の preimage 耐性)
//   - CSRF トークン漏洩からも raw session を復元できない
//   - セッション再生成で自動的にローテーションする
//   - 複数タブ・古いフォームでも安定する
func csrfToken(rawSessionToken []byte) string {
	h := sha256.New()
	h.Write([]byte("hokora/csrf/v1"))
	h.Write(rawSessionToken)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// verifyCSRF は提示された CSRF トークンを検証する。
func verifyCSRF(rawSessionToken []byte, presented string) error {
	// 秘密同士の比較なので定数時間で行う(AGENTS.md ルール 4)。
	if !constantTimeEqual([]byte(csrfToken(rawSessionToken)), []byte(presented)) {
		return ErrInvalidCSRF
	}
	return nil
}

// ---- Cookie ----

// setSessionCookie はセッション Cookie を設定する(DESIGN §7.2)。
//
// **Domain 属性を付けない。** `__Host-` prefix の要件であり、付けると
// ブラウザが Cookie 自体を拒否する。
func setSessionCookie(w http.ResponseWriter, encoded string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie は Cookie を消す。DB 側の削除と対で使う。
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// sessionTokenFromRequest は Cookie から生のセッショントークンを取り出す。
func sessionTokenFromRequest(r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, ErrNoSession
	}
	return DecodeSessionToken(cookie.Value)
}

// ---- Fetch Metadata / Origin(DESIGN §7.3) ----

// checkFetchMetadata はログイン POST のクロスオリジン検証を行う。
//
// **pre-auth の防御である。** セッションがまだ無いので CSRF トークンを
// 使えず、Fetch Metadata と Origin で代替する。
//
//  1. Sec-Fetch-Site: same-origin なら通す
//  2. 無ければ Origin を **scheme / host / port の完全一致** で検証する
//  3. Origin: null は拒否する
//  4. 両方欠けていたら拒否する
//
// 「Origin が存在すること」ではなく完全一致を見る(AGENTS.md ルール 48)。
// 存在確認だけでは、攻撃者のページからの POST も Origin を持つため通る。
func checkFetchMetadata(r *http.Request) error {
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
	case "same-origin":
		return nil
	case "":
		// Fetch Metadata を送らないブラウザ。Origin で検証する。
	default:
		// cross-site / same-site / none。いずれも許さない。
		return ErrCrossOrigin
	}

	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		// 両方欠けている、あるいは opaque origin。拒否する。
		return ErrCrossOrigin
	}
	if origin != requestOrigin(r) {
		return ErrCrossOrigin
	}
	return nil
}

// requestOrigin はリクエスト自身の origin を組み立てる。
//
// Web UI は TLS でのみ提供されるので scheme は https で固定する。Host は
// ブラウザが送った値だが、TLS の SNI と証明書に一致しない Host では
// そもそも接続が成立しない。
func requestOrigin(r *http.Request) string {
	return "https://" + r.Host
}

// ---- セッションの永続化 ----

// createSession はセッション行を作る。**保存するのはハッシュだけ。**
//
// **C9 の再読検証を経た呼び出し以外から呼んではならない**(DESIGN §4.4)。
// パスワードを検証してからセッションを作るまでの間にパスワードが変更されると、
// 旧パスワード由来のセッションが生き残る。Login はこの関数を「password_hash を
// 再読して一致を確認した後」の同一トランザクション内でのみ呼ぶ。
// **ここに直接セッションを作る新しい経路を足すと、その競合が戻ってくる。**
func createSession(ctx context.Context, ex execer, userID int64, raw []byte, remoteAddr string, now time.Time) error {
	_, err := ex.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at, remote_addr)
		VALUES (?, ?, ?, ?, ?, ?)`,
		hashSessionToken(raw), userID, now.Unix(),
		now.Add(SessionAbsoluteTTL).Unix(), now.Unix(), remoteAddr,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// LookupSession はセッションを検証し、ユーザーを返す。
//
// **絶対期限と idle 期限の両方を、各リクエストで検査する**
// (AGENTS.md ルール 52)。sweep は掃除であって期限判定ではない。
//
// **ユーザーの disabled も毎回読み直す**(§4.5)。セッションは認証の証明で
// あって、認可の証明ではない。
//
// 有効だった場合は last_seen_at を更新する(idle 期限の起点)。
func LookupSession(ctx context.Context, db *sql.DB, raw []byte, now time.Time) (*SessionUser, error) {
	var (
		userID               int64
		username             string
		mustChange, disabled int
		expiresAt, lastSeen  int64
	)
	hash := hashSessionToken(raw)
	err := db.QueryRowContext(ctx, `
		SELECT s.user_id, u.username, u.must_change_pw, u.disabled, s.expires_at, s.last_seen_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?`, hash,
	).Scan(&userID, &username, &mustChange, &disabled, &expiresAt, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("lookup session: %w", err)
	}

	if disabled != 0 {
		return nil, ErrNoSession
	}
	// 絶対期限。
	if !now.Before(time.Unix(expiresAt, 0)) {
		return nil, ErrNoSession
	}
	// idle 期限。
	if !now.Before(time.Unix(lastSeen, 0).Add(SessionIdleTTL)) {
		return nil, ErrNoSession
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`, now.Unix(), hash); err != nil {
		return nil, fmt.Errorf("touch session: %w", err)
	}

	return &SessionUser{
		UserID:       userID,
		Username:     username,
		MustChangePW: mustChange != 0,
		CSRFToken:    csrfToken(raw),
		ExpiresAt:    time.Unix(expiresAt, 0).UTC(),
		LastSeenAt:   now.UTC(),
	}, nil
}

// DeleteSession は 1 件のセッションを削除する(logout)。
//
// **session は物理削除を許可する**(AGENTS.md ルール 56 の例外)。
func DeleteSession(ctx context.Context, ex execer, raw []byte) error {
	if _, err := ex.ExecContext(ctx,
		`DELETE FROM sessions WHERE token_hash = ?`, hashSessionToken(raw)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// deleteSessionsByUser は当該ユーザーの全セッションを削除する。
//
// パスワード変更・ユーザー無効化で使う(AGENTS.md ルール 53)。
func deleteSessionsByUser(ctx context.Context, ex execer, userID int64) error {
	if _, err := ex.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}
	return nil
}

// SweepSessions は期限切れのセッション行を掃除する。
//
// **これは期限判定ではない**(それは LookupSession が毎回行う)。
func SweepSessions(ctx context.Context, db *sql.DB, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?`,
		now.Unix(), now.Add(-SessionIdleTTL).Unix())
	if err != nil {
		return 0, fmt.Errorf("sweep sessions: %w", err)
	}
	return res.RowsAffected()
}
