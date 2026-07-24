package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// uiFixture は Web UI のテスト一式である。
type uiFixture struct {
	ui    *uiServer
	vault *Vault
	store *Store
	mk    []byte

	userID  int64
	rawSess []byte
	csrf    string
}

// newUIFixture は **sealed のまま** の UI を返す(argon2 は keyring の 1 回のみ)。
func newUIFixture(t *testing.T) *uiFixture {
	t.Helper()

	v, store, mk := newTestVault(t)
	ui, err := newUIServer(v, discardLogger(), newRateLimiter(unsealRate, 1))
	if err != nil {
		t.Fatalf("newUIServer: %v", err)
	}
	ui.now = func() time.Time { return vaultNow }

	f := &uiFixture{ui: ui, vault: v, store: store, mk: mk}
	f.userID = newTestUser(t, store)
	f.rawSess = newTestSession(t, store, f.userID)
	f.csrf = csrfToken(f.rawSess)
	return f
}

// unseal は vault を開ける(argon2 を 1 回払う)。
func (f *uiFixture) unseal(t *testing.T) {
	t.Helper()
	unsealForTest(t, f.vault, f.mk)
}

// get は認証済みの GET を送る。
func (f *uiFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, http.MethodGet, path, nil, true)
}

// post は認証済みの POST を送る(CSRF トークンを自動で載せる)。
func (f *uiFixture) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	if form == nil {
		form = url.Values{}
	}
	if form.Get("csrf_token") == "" {
		form.Set("csrf_token", f.csrf)
	}
	return f.do(t, http.MethodPost, path, form, true)
}

func (f *uiFixture) do(t *testing.T, method, path string, form url.Values, withSession bool) *httptest.ResponseRecorder {
	t.Helper()

	var r *http.Request
	if form != nil {
		r = httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequestWithContext(t.Context(), method, path, nil)
	}
	r.Host = "hokora.internal:8443"
	r.RemoteAddr = "10.8.0.9:51234"
	if withSession {
		// リクエスト側の Cookie なので属性は関係ない(サーバーが出す側は
		// TestSessionCookieAttributes が見ている)。
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: base64Session(f.rawSess)}) //nolint:gosec // G124
	}

	w := httptest.NewRecorder()
	withUIHeaders(f.ui.uiMux()).ServeHTTP(w, r)
	return w
}

// seedSecret は project / environment / item を用意する。
func (f *uiFixture) seedSecret(t *testing.T, key, value string) *EnvironmentRef {
	t.Helper()

	projectID, err := CreateProject(t.Context(), f.store.DB(), testProjectSlug, "", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	envID, err := CreateEnvironment(t.Context(), f.store.DB(), testProjectSlug, testEnvSlug, "", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateEnvironment: %v", err)
	}

	env, err := ResolveEnvironment(t.Context(), f.store.DB(), testProjectSlug, testEnvSlug)
	if err != nil {
		t.Fatalf("ResolveEnvironment: %v", err)
	}
	// 作成関数が返す ID が、解決結果と一致すること(監査ログの
	// target_*_id はこの ID で記録される)。
	if env.ProjectID != projectID || env.EnvironmentID != envID {
		t.Fatalf("resolved ids = %d/%d, want %d/%d",
			env.ProjectID, env.EnvironmentID, projectID, envID)
	}
	if err := PutSecret(t.Context(), f.vault, env, key, []byte(value), f.auditCtx()); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	return env
}

func (f *uiFixture) auditCtx() auditCtx {
	return userAudit(f.userID, "10.8.0.9", vaultNow)
}

// ---- ヘッダ ----

// **全レスポンスに DESIGN §8.3 のヘッダが付く。**
func TestUISecurityHeaders(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	w := f.do(t, http.MethodGet, "/ui/login", nil, false)

	want := map[string]string{
		"Cache-Control":             "no-store, no-cache, must-revalidate, private",
		"Pragma":                    "no-cache",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000",
	}
	for header, value := range want {
		if got := w.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	// **CDN から何も読み込まない**(ルール 42)。
	for _, directive := range []string{
		"default-src 'self'", "script-src 'self'", "style-src 'self'",
		"frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP %q is missing %q", csp, directive)
		}
	}
	// インラインを許す指定が無いこと(bfcache.js を別ファイルにしている理由)。
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP allows inline or eval: %q", csp)
	}
}

// **レスポンス圧縮を有効にしない**(DESIGN §9.5)。
func TestUIDoesNotCompressResponses(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ui/login", nil)
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	w := httptest.NewRecorder()
	withUIHeaders(f.ui.uiMux()).ServeHTTP(w, r)

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want none (BREACH 対策のため圧縮しない)", got)
	}
}

// ---- 認証 ----

// セッションが無ければログインへ送られる。
func TestUIRequiresASession(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)

	for _, path := range []string{"/ui/", "/ui/machines", "/ui/users", "/ui/audit", "/ui/password"} {
		w := f.do(t, http.MethodGet, path, nil, false)
		if w.Code != http.StatusSeeOther {
			t.Errorf("%s = %d, want 303", path, w.Code)
		}
		if got := w.Header().Get("Location"); got != "/ui/login" {
			t.Errorf("%s redirected to %q, want /ui/login", path, got)
		}
	}
}

// ログイン POST は Fetch Metadata / Origin で守られる(DESIGN §7.3)。
func TestUILoginRequiresSameOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"same-origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusUnauthorized},
		{"matching origin", map[string]string{"Origin": "https://hokora.internal:8443"}, http.StatusUnauthorized},
		{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"foreign origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"null origin", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"no headers", nil, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newUIFixture(t)
			form := url.Values{"username": {testUsername}, "password": {"wrong-password"}}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ui/login",
				strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Host = "hokora.internal:8443"
			r.RemoteAddr = "10.8.0.9:51234"
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			withUIHeaders(f.ui.uiMux()).ServeHTTP(w, r)

			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// **CSRF トークンなしの POST が全て拒否される**(M5 完了条件)。
func TestUIPostsRequireCSRF(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)

	paths := []string{
		"/ui/logout",
		"/ui/password",
		"/ui/projects",
		"/ui/projects/" + testProjectSlug + "/delete",
		"/ui/projects/" + testProjectSlug + "/environments",
		envPath(env) + "/delete",
		envPath(env) + "/items",
		envPath(env) + "/items/DATABASE_URL/reveal",
		envPath(env) + "/items/DATABASE_URL/delete",
		envPath(env) + "/items/DATABASE_URL/history/1/reveal",
		"/ui/machines",
		"/ui/machines/1/rotate",
		"/ui/machines/1/disable",
		"/ui/machines/1/grants",
		"/ui/machines/1/grants/1/delete",
		"/ui/users",
		"/ui/users/2/disable",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			// トークン無し。
			if w := f.do(t, http.MethodPost, path, url.Values{}, true); w.Code != http.StatusForbidden {
				t.Errorf("without a csrf token = %d, want 403", w.Code)
			}
			// 別セッション由来のトークン。
			other := newTestSession(t, f.store, f.userID)
			form := url.Values{"csrf_token": {csrfToken(other)}}
			if w := f.do(t, http.MethodPost, path, form, true); w.Code != http.StatusForbidden {
				t.Errorf("with another session's csrf token = %d, want 403", w.Code)
			}
		})
	}
}

// C: CSRF 拒否は監査される(ルール 22/26)。actor は拒否されたセッションの
// user、理由は invalid_csrf。fail open(拒否そのものはどのみち確定して
// いるので、記録できなくても 403 のまま)。
func TestUICSRFRejectionIsAudited(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	// トークン無しの POST。
	if w := f.do(t, http.MethodPost, "/ui/logout", url.Values{}, true); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}

	var (
		actor  string
		userID sql.NullInt64
		detail string
	)
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT actor, actor_user_id, COALESCE(detail, '') FROM audit_logs
		WHERE action = ? AND result = ?`,
		string(ActionCSRFReject), string(ResultFailure)).Scan(&actor, &userID, &detail); err != nil {
		t.Fatalf("select audit row: %v", err)
	}

	if want := actorUser(f.userID); actor != want {
		t.Errorf("actor = %q, want %q", actor, want)
	}
	if !userID.Valid || userID.Int64 != f.userID {
		t.Errorf("actor_user_id = %v, want %d", userID, f.userID)
	}
	if !strings.Contains(detail, `"reason":"`+ReasonInvalidCSRF+`"`) {
		t.Errorf("detail = %q, want reason = %q", detail, ReasonInvalidCSRF)
	}
}

// ---- 初回フロー(DESIGN §8.3) ----

// **must_change_pw ならパスワード変更へ送られる。**
func TestUIMustChangePasswordRedirects(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	if _, err := f.store.DB().ExecContext(t.Context(),
		`UPDATE users SET must_change_pw = 1 WHERE id = ?`, f.userID); err != nil {
		t.Fatalf("set must_change_pw: %v", err)
	}

	for _, path := range []string{"/ui/", "/ui/machines", "/ui/audit"} {
		w := f.get(t, path)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/password" {
			t.Errorf("%s = %d %q, want a redirect to /ui/password", path, w.Code, w.Header().Get("Location"))
		}
	}
	// パスワード変更画面自体は開ける(無限リダイレクトにならない)。
	if w := f.get(t, "/ui/password"); w.Code != http.StatusOK {
		t.Errorf("/ui/password = %d, want 200", w.Code)
	}
}

// **パスワード変更は sealed 状態でも動作する**(M5 完了条件)。
func TestUIPasswordChangeWorksWhileSealed(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t) // sealed のまま
	if f.vault.Status().State != StateSealed {
		t.Fatal("test setup: the vault is not sealed")
	}

	if w := f.get(t, "/ui/password"); w.Code != http.StatusOK {
		t.Fatalf("/ui/password while sealed = %d, want 200", w.Code)
	}

	const next = "a-brand-new-passphrase"
	w := f.post(t, "/ui/password", url.Values{
		"current_password": {testPassword},
		"new_password":     {next},
		"confirm_password": {next},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("password change while sealed = %d, want 303 (body %q)", w.Code, w.Body.String())
	}
	// sealed なので unseal へ送られる。
	if got := w.Header().Get("Location"); got != "/ui/unseal" {
		t.Errorf("redirected to %q, want /ui/unseal", got)
	}
	// **セッションが張り替えられる**(全セッションを消すため)。
	if len(w.Result().Cookies()) == 0 {
		t.Error("no new session cookie was issued")
	}
}

// sealed では通常の画面が unseal へ送られる。
func TestUISealedRedirectsToUnseal(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)

	for _, path := range []string{"/ui/", "/ui/machines", "/ui/users", "/ui/audit"} {
		w := f.get(t, path)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/unseal" {
			t.Errorf("%s = %d %q, want a redirect to /ui/unseal", path, w.Code, w.Header().Get("Location"))
		}
	}
}

// **Web UI から unseal できる**(M5 完了条件)。
func TestUIUnseal(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)

	if w := f.get(t, "/ui/unseal"); w.Code != http.StatusOK {
		t.Fatalf("/ui/unseal = %d, want 200", w.Code)
	}

	// 誤ったキーでは開かない。
	w := f.post(t, "/ui/unseal", url.Values{"master_key": {EncodeMasterKey(flipByte(f.mk, 0))}})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unseal with a wrong key = %d, want 401", w.Code)
	}
	if f.vault.Status().State != StateSealed {
		t.Fatal("the vault was unsealed by a wrong key")
	}

	w = f.post(t, "/ui/unseal", url.Values{"master_key": {EncodeMasterKey(f.mk)}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("unseal = %d, want 303 (body %q)", w.Code, w.Body.String())
	}
	if f.vault.Status().State != StateUnsealed {
		t.Fatal("the vault was not unsealed")
	}
}

// ---- secret の一連の流れ ----

// ログイン後の project 作成 → environment 作成 → item 作成 → 平文表示 →
// 更新 → 履歴 → 削除(M5 完了条件)。
func TestUISecretLifecycle(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	// project
	if w := f.post(t, "/ui/projects", url.Values{"slug": {"myapp"}, "name": {"My App"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("create project = %d (body %q)", w.Code, w.Body.String())
	}
	// environment
	if w := f.post(t, "/ui/projects/myapp/environments", url.Values{"slug": {"prod"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("create environment = %d", w.Code)
	}
	// item
	if w := f.post(t, "/ui/projects/myapp/prod/items",
		url.Values{"key": {"DATABASE_URL"}, "value": {testSecretValue}}); w.Code != http.StatusSeeOther {
		t.Fatalf("create item = %d (body %q)", w.Code, w.Body.String())
	}

	// **一覧に平文が含まれない**(M5 完了条件)。
	w := f.get(t, "/ui/projects/myapp/prod")
	if w.Code != http.StatusOK {
		t.Fatalf("environment page = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), testSecretValue) {
		t.Error("the item list contains the plaintext")
	}
	if !strings.Contains(w.Body.String(), "DATABASE_URL") {
		t.Error("the item list does not show the key")
	}

	// reveal では出る。**監査ログにも残る。**
	before := countAuditLogs(t, f.store.DB(), ActionSecretReveal)
	w = f.post(t, "/ui/projects/myapp/prod/items/DATABASE_URL/reveal", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("reveal = %d (body %q)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), testSecretValue) {
		t.Error("reveal did not show the plaintext")
	}
	if after := countAuditLogs(t, f.store.DB(), ActionSecretReveal); after != before+1 {
		t.Errorf("%d reveal audit rows, want %d", after, before+1)
	}
	// **平文ページは data-bfcache="replace"**(DESIGN §9.3)。
	assertBFCacheReplace(t, w.Body.String(), "/ui/projects/myapp/prod")

	// 更新(追記される)。
	updated := "postgres://user:" + "new@localhost/db"
	if w := f.post(t, "/ui/projects/myapp/prod/items/DATABASE_URL",
		url.Values{"value": {updated}}); w.Code != http.StatusSeeOther {
		t.Fatalf("update item = %d", w.Code)
	}

	// 履歴に 2 版ある。
	w = f.get(t, "/ui/projects/myapp/prod/items/DATABASE_URL/history")
	if w.Code != http.StatusOK {
		t.Fatalf("history = %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, testSecretValue) || strings.Contains(body, updated) {
		t.Error("the history page contains plaintext")
	}

	// 過去版の reveal。
	w = f.post(t, "/ui/projects/myapp/prod/items/DATABASE_URL/history/1/reveal", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("reveal version 1 = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), testSecretValue) {
		t.Error("reveal of version 1 did not show the original value")
	}
	assertBFCacheReplace(t, w.Body.String(), "/ui/projects/myapp/prod")

	// 削除すると一覧から消える。
	if w := f.post(t, "/ui/projects/myapp/prod/items/DATABASE_URL/delete", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("delete item = %d", w.Code)
	}
	w = f.get(t, "/ui/projects/myapp/prod")
	if strings.Contains(w.Body.String(), "DATABASE_URL") {
		t.Error("the deleted item is still listed")
	}
}

// ---- Machine / ユーザー ----

// **credential は作成時と再発行時に一度だけ表示される**(AGENTS.md ルール 50)。
func TestUIMachineCredentialIsShownOnce(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	w := f.post(t, "/ui/machines", url.Values{"name": {"app"}})
	if w.Code != http.StatusOK {
		t.Fatalf("create machine = %d (body %q)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `class="credential"`) || !strings.Contains(body, "HOKORA_CLIENT_SECRET") {
		t.Fatal("the credential was not shown")
	}
	// **平文ページなので replace。**
	assertBFCacheReplace(t, body, "/ui/machines")

	// 一覧を開き直すと、もう出ない。
	w = f.get(t, "/ui/machines")
	if strings.Contains(w.Body.String(), `class="credential"`) {
		t.Error("the credential is shown again on a plain listing")
	}

	// 再発行でも同じ扱い。
	w = f.post(t, "/ui/machines/1/rotate", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate = %d (body %q)", w.Code, w.Body.String())
	}
	assertBFCacheReplace(t, w.Body.String(), "/ui/machines")
}

// **environment 画面からサーバーを作ると、その環境への grant 付きで作られ、
// credential を一度だけ表示する**(#9)。
//
// credential も平文なので、平文ページと同じく data-bfcache="replace" で退避する
// (ルール 50)。
func TestUICreateMachineForEnv(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)

	w := f.post(t, envPath(env)+"/machines", url.Values{"name": {"請求バッチ"}})
	if w.Code != http.StatusOK {
		t.Fatalf("create machine for env = %d (body %q)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// **credential を一度だけ表示する。**
	if !strings.Contains(body, `class="credential"`) || !strings.Contains(body, "HOKORA_CLIENT_SECRET") {
		t.Fatal("the credential was not shown")
	}
	// **平文ページなので replace(退避先は environment ページ)。**
	assertBFCacheReplace(t, body, envPath(env))

	// **作られた machine はこの環境への grant を持つ。**
	var machineID int64
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT id FROM machines`).Scan(&machineID); err != nil {
		t.Fatalf("select machine id: %v", err)
	}
	granted, err := HasGrant(t.Context(), f.store.DB(), machineID, env.EnvironmentID)
	if err != nil {
		t.Fatalf("HasGrant: %v", err)
	}
	if !granted {
		t.Error("the created machine is not granted to the environment")
	}

	// 一覧を開き直すと credential はもう出ない。
	if w := f.get(t, "/ui/machines"); strings.Contains(w.Body.String(), `class="credential"`) {
		t.Error("the credential is shown again on a plain listing")
	}
}

// **environment 画面からのサーバー作成でも、空の名前は弾く**(#7 の必須検証)。
//
// 弾いたときは machine 行を残さない(400 を返すだけで作らない)。
func TestUICreateMachineForEnvRejectsAnEmptyName(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)

	w := f.post(t, envPath(env)+"/machines", url.Values{"name": {"   "}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty name = %d, want 400 (body %q)", w.Code, w.Body.String())
	}
	var n int
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM machines`).Scan(&n); err != nil {
		t.Fatalf("count machines: %v", err)
	}
	if n != 0 {
		t.Errorf("%d machine rows were created for an empty name", n)
	}
}

// **一覧に client_id を出さない**(#7)。作成・再発行時の credential ブロックだけが
// client_id を見せ、サーバー一覧は名前で識別する。
func TestUIMachineListOmitsClientID(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	const machineName = "billing-batch-server"
	w := f.post(t, "/ui/machines", url.Values{"name": {machineName}})
	if w.Code != http.StatusOK {
		t.Fatalf("create machine = %d (body %q)", w.Code, w.Body.String())
	}

	// **client_id は生成値なので DB から読む**(テストデータの値に依存しない)。
	var clientID string
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT client_id FROM machines`).Scan(&clientID); err != nil {
		t.Fatalf("select client_id: %v", err)
	}
	if clientID == "" {
		t.Fatal("test setup: the machine has no client_id")
	}
	// **作成時の credential ブロックは client_id を見せる**(反対側の取り違えを防ぐ)。
	if !strings.Contains(w.Body.String(), clientID) {
		t.Error("the creation page does not show the client_id in the credential block")
	}

	// **一覧には client_id が出ない。** 名前は識別子として出る。
	body := f.get(t, "/ui/machines").Body.String()
	if strings.Contains(body, clientID) {
		t.Errorf("the machine list renders the client_id %q", clientID)
	}
	if !strings.Contains(body, machineName) {
		t.Error("the machine list does not show the machine name")
	}
}

// ユーザー作成では初期パスワードを一度だけ表示する。
func TestUICreateUserShowsTheInitialPasswordOnce(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	w := f.post(t, "/ui/users", url.Values{"username": {"operator"}})
	if w.Code != http.StatusOK {
		t.Fatalf("create user = %d (body %q)", w.Code, w.Body.String())
	}
	// 一覧ページには「初期パスワードはサーバーが生成します」という説明文も
	// あるので、文言ではなく **credential ブロックの有無** で判定する。
	if !strings.Contains(w.Body.String(), `class="credential"`) {
		t.Fatal("the initial password block was not shown")
	}
	assertBFCacheReplace(t, w.Body.String(), "/ui/users")

	w = f.get(t, "/ui/users")
	if strings.Contains(w.Body.String(), `class="credential"`) {
		t.Error("the initial password is shown again on a plain listing")
	}
}

// 自分自身は無効化できない(全 admin を締め出す事故を防ぐ)。
func TestUICannotDisableYourself(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	w := f.post(t, "/ui/users/"+itoa(f.userID)+"/disable", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if _, err := LookupSession(t.Context(), f.store.DB(), f.rawSess, vaultNow); err != nil {
		t.Errorf("the session was invalidated: %v", err)
	}
}

// ---- 監査ログ ----

func TestUIAuditPage(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	f.seedSecret(t, "DATABASE_URL", testSecretValue)

	w := f.get(t, "/ui/audit")
	if w.Code != http.StatusOK {
		t.Fatalf("audit page = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, string(ActionSecretWrite)) {
		t.Error("the audit page does not list the write")
	}
	// **監査ログに平文は入らない**(THREAT_MODEL §10.6)。
	if strings.Contains(body, testSecretValue) {
		t.Error("the audit page contains a secret value")
	}
}

// ---- 補助 ----

// assertBFCacheReplace は平文ページの bfcache 設定を確認する。
//
// **平文ページは data-bfcache="replace"**、通常のページは "reload"
// (DESIGN §9.3)。replace は DOM を消してから安全な GET へ退避するので、
// POST 結果ページでも再送確認ダイアログが出ない。
func assertBFCacheReplace(t *testing.T, body, wantURL string) {
	t.Helper()

	if !strings.Contains(body, `data-bfcache="replace"`) {
		t.Error(`the plaintext page is not marked data-bfcache="replace"`)
	}
	if !strings.Contains(body, `data-bfcache-url="`+wantURL+`"`) {
		t.Errorf("the page does not carry the escape url %q", wantURL)
	}
	// bfcache.js を読み込んでいること(CSP を維持するため外部ファイル)。
	if !strings.Contains(body, `/ui/static/bfcache.js`) {
		t.Error("the page does not load bfcache.js")
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// assertBFCacheReload は通常のページの bfcache 設定を確認する。
//
// **通常のページは "reload"**(DESIGN §9.3 の設計要点 3)。全ページを
// "replace" にするとフォーム入力中の「戻る」がダッシュボード行きになり、
// 逆に全ページを固定文字列にすると平文ページの退避が効かなくなる。
// **どちらの向きの取り違えも検出する必要がある。**
func assertBFCacheReload(t *testing.T, body string) {
	t.Helper()

	if !strings.Contains(body, `data-bfcache="reload"`) {
		t.Error(`an ordinary page is not marked data-bfcache="reload"`)
	}
	if strings.Contains(body, `data-bfcache="replace"`) {
		t.Error(`an ordinary page is marked data-bfcache="replace"`)
	}
	if !strings.Contains(body, `/ui/static/bfcache.js`) {
		t.Error("the page does not load bfcache.js")
	}
}

// doWithCookie は任意のセッション Cookie とヘッダでリクエストを送る。
//
// f.do は fixture のセッションに固定されているので、**ログインで発行された
// 新しい Cookie** や、**張り替え前の古い Cookie** を使う検査には使えない。
func (f *uiFixture) doWithCookie(t *testing.T, method, path string, form url.Values,
	cookie string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	var r *http.Request
	if form != nil {
		r = httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequestWithContext(t.Context(), method, path, nil)
	}
	r.Host = "hokora.internal:8443"
	r.RemoteAddr = "10.8.0.9:51234"
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie}) //nolint:gosec // G124
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	withUIHeaders(f.ui.uiMux()).ServeHTTP(w, r)
	return w
}

// sessionCookieValue はレスポンスが発行したセッション Cookie の値を返す。
func sessionCookieValue(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c.Value
		}
	}
	t.Fatalf("no %s cookie was issued", SessionCookieName)
	return ""
}

// countSessions は当該ユーザーのセッション行数を返す。
func countSessions(t *testing.T, db *sql.DB, userID int64) int {
	t.Helper()

	var n int
	if err := db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM sessions WHERE user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// ---- 静的アセット(DESIGN §9.4) ----

// **static/ だけが認証不要で配られる。**
//
// ログイン画面が style.css と bfcache.js を読み込むため、ここを認証必須に
// すると **平文ページの bfcache 対策(§9.3)が読み込まれなくなる。** 逆に
// 認証不要の配信範囲が static/ を超えると、テンプレートの中身が見える。
func TestUIStaticAssetsAreServedWithoutASession(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)

	for _, tt := range []struct{ path, want string }{
		{"/ui/static/style.css", "body"},
		{"/ui/static/bfcache.js", "pageshow"},
	} {
		w := f.do(t, http.MethodGet, tt.path, nil, false)
		if w.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", tt.path, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), tt.want) {
			t.Errorf("%s does not contain %q", tt.path, tt.want)
		}
	}

	// **テンプレートは配らない。** パスの正規化で templates/ へ抜けられない。
	for _, path := range []string{
		"/ui/static/../templates/base.html",
		"/ui/static/templates/base.html",
	} {
		w := f.do(t, http.MethodGet, path, nil, false)
		if w.Code == http.StatusOK {
			t.Errorf("%s = 200, want a redirect or 404", path)
		}
		if strings.Contains(w.Body.String(), "{{define") {
			t.Errorf("%s served a template source", path)
		}
	}
}

// ---- 初回ログインの一連の流れ(DESIGN §8.3、M5 完了条件) ----

// **ログイン → パスワード変更 → セッション再生成 → unseal が動く。**
//
// 個々のハンドラのテストでは、この順序が繋がっていることを確認できない。
// 初期 admin は must_change_pw = 1 かつ sealed で始まるので、**この経路が
// 切れていると初期セットアップが完了できず、他の全ての画面に到達できない。**
func TestUIFirstLoginFlow(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t) // sealed のまま
	if _, err := f.store.DB().ExecContext(t.Context(),
		`UPDATE users SET must_change_pw = 1 WHERE id = ?`, f.userID); err != nil {
		t.Fatalf("set must_change_pw: %v", err)
	}

	// 1. ログイン(pre-auth の CSRF 対策は Fetch Metadata である)。
	w := f.doWithCookie(t, http.MethodPost, "/ui/login",
		url.Values{"username": {testUsername}, "password": {testPassword}},
		"", map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303 (body %q)", w.Code, w.Body.String())
	}
	// **must_change_pw ならパスワード変更へ送られる。**
	if got := w.Header().Get("Location"); got != "/ui/password" {
		t.Fatalf("login redirected to %q, want /ui/password", got)
	}
	first := sessionCookieValue(t, w)

	// 2. sealed でもパスワード変更画面が開ける。
	w = f.doWithCookie(t, http.MethodGet, "/ui/password", nil, first, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("/ui/password = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "初回ログインです") {
		t.Error("the password page does not tell the user why they are here")
	}

	firstRaw, err := DecodeSessionToken(first)
	if err != nil {
		t.Fatalf("DecodeSessionToken: %v", err)
	}

	// 3. パスワード変更。**セッションが再生成される。**
	const next = "another-good-passphrase"
	w = f.doWithCookie(t, http.MethodPost, "/ui/password", url.Values{
		"csrf_token":       {csrfToken(firstRaw)},
		"current_password": {testPassword},
		"new_password":     {next},
		"confirm_password": {next},
	}, first, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("password change = %d, want 303 (body %q)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/ui/unseal" {
		t.Fatalf("password change redirected to %q, want /ui/unseal", got)
	}
	second := sessionCookieValue(t, w)
	if second == first {
		t.Fatal("the session token was reused after a password change")
	}

	// **古いセッションは使えない**(ルール 53)。
	if w := f.doWithCookie(t, http.MethodGet, "/ui/password", nil, first, nil); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/ui/login" {
		t.Errorf("the old session still works: %d %q", w.Code, w.Header().Get("Location"))
	}

	secondRaw, err := DecodeSessionToken(second)
	if err != nil {
		t.Fatalf("DecodeSessionToken: %v", err)
	}
	// **CSRF トークンもローテーションする**(セッションから導出しているため)。
	if csrfToken(secondRaw) == csrfToken(firstRaw) {
		t.Error("the csrf token did not rotate with the session")
	}
	// 古いトークンでは POST が通らない。
	if w := f.doWithCookie(t, http.MethodPost, "/ui/unseal",
		url.Values{"csrf_token": {csrfToken(firstRaw)}, "master_key": {EncodeMasterKey(f.mk)}},
		second, nil); w.Code != http.StatusForbidden {
		t.Fatalf("unseal with the previous csrf token = %d, want 403", w.Code)
	}

	// 4. sealed なので通常の画面は unseal へ送られる。
	if w := f.doWithCookie(t, http.MethodGet, "/ui/", nil, second, nil); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/ui/unseal" {
		t.Fatalf("/ui/ = %d %q, want a redirect to /ui/unseal", w.Code, w.Header().Get("Location"))
	}

	// 5. unseal(新しいセッションの CSRF トークンで)。
	w = f.doWithCookie(t, http.MethodPost, "/ui/unseal",
		url.Values{"csrf_token": {csrfToken(secondRaw)}, "master_key": {EncodeMasterKey(f.mk)}},
		second, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/" {
		t.Fatalf("unseal = %d %q, want a redirect to /ui/", w.Code, w.Header().Get("Location"))
	}
	if f.vault.Status().State != StateUnsealed {
		t.Fatal("the vault is still sealed")
	}

	// 6. unseal 済みなら unseal 画面は開かない(戻ってきても迷わせない)。
	if w := f.doWithCookie(t, http.MethodGet, "/ui/unseal", nil, second, nil); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/ui/" {
		t.Errorf("/ui/unseal while unsealed = %d %q, want a redirect to /ui/", w.Code, w.Header().Get("Location"))
	}

	// 7. ダッシュボードが開ける(初期セットアップの完了)。
	if w := f.doWithCookie(t, http.MethodGet, "/ui/", nil, second, nil); w.Code != http.StatusOK {
		t.Fatalf("/ui/ after unseal = %d, want 200", w.Code)
	}
}

// **ログアウトはセッションを消し、Cookie を落とす。**
//
// must_change_pw のユーザーでも動くこと。ここを塞ぐと、パスワードを変更
// できない状況(パスワードを控え損ねた等)で抜け出せなくなる。
func TestUILogoutEndsTheSession(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t) // sealed のまま(logout は sealedOK)
	if _, err := f.store.DB().ExecContext(t.Context(),
		`UPDATE users SET must_change_pw = 1 WHERE id = ?`, f.userID); err != nil {
		t.Fatalf("set must_change_pw: %v", err)
	}

	w := f.post(t, "/ui/logout", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d, want 303 (body %q)", w.Code, w.Body.String())
	}
	// **/ui/password へ吸い込まれないこと**(must_change_pw の例外)。
	if got := w.Header().Get("Location"); got != "/ui/login" {
		t.Fatalf("logout redirected to %q, want /ui/login", got)
	}
	if got := sessionCookieValue(t, w); got != "" {
		t.Errorf("the session cookie was not cleared: %q", got)
	}
	if n := countSessions(t, f.store.DB(), f.userID); n != 0 {
		t.Errorf("%d session rows remain, want 0", n)
	}
	// 同じ Cookie はもう使えない。
	if w := f.get(t, "/ui/password"); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/ui/login" {
		t.Errorf("the session still works after logout: %d %q", w.Code, w.Header().Get("Location"))
	}
}

// **セッションは毎リクエスト検査される**(ルール 51-52、M5 完了条件)。
//
// sweep はメモリ / DB の掃除であって認証上の期限判定ではない。sweep を
// 動かさずに idle 期限が効くこと、ユーザー無効化が即座に効くことを見る。
func TestUISessionIsRecheckedOnEveryRequest(t *testing.T) {
	t.Parallel()

	// sealed のままで確認する。**認証の検査は sealed 判定より前**にあるので、
	// unseal を払わずに検査できる(/ui/password は sealedOK)。
	f := newUIFixture(t)

	if w := f.get(t, "/ui/password"); w.Code != http.StatusOK {
		t.Fatalf("test setup: /ui/password = %d, want 200", w.Code)
	}

	// idle 期限を越えた時刻から見ると、同じ Cookie が通らない。
	// **sweepSessions は呼んでいない。**
	f.ui.now = func() time.Time { return vaultNow.Add(SessionIdleTTL + time.Minute) }
	w := f.get(t, "/ui/password")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/login" {
		t.Fatalf("an idle session = %d %q, want a redirect to /ui/login", w.Code, w.Header().Get("Location"))
	}
	// 無効なセッションの Cookie は落とす(次のログインで持ち越さない)。
	if got := sessionCookieValue(t, w); got != "" {
		t.Errorf("the stale cookie was not cleared: %q", got)
	}

	// ユーザー無効化も即座に効く。
	f.ui.now = func() time.Time { return vaultNow }
	if err := DisableUser(t.Context(), f.store.DB(), discardLogger(), f.userID, f.auditCtx()); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if w := f.get(t, "/ui/password"); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/ui/login" {
		t.Errorf("a disabled user still has a session: %d %q", w.Code, w.Header().Get("Location"))
	}
}

// ---- project / environment の画面と論理削除 ----

// **project 詳細と論理削除が動き、削除した配下へ到達できない。**
//
// DeleteProject は配下の environment / item を残す(監査ログの
// target_*_id を解決可能に保つため)。**祖先の deleted_at を検査していない
// 経路が 1 つでもあると、削除したはずの secret が読める**
// (THREAT_MODEL §11.1)。
func TestUIProjectPagesAndLogicalDeletion(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)

	// project 詳細に environment が並ぶ。
	w := f.get(t, "/ui/projects/"+testProjectSlug)
	if w.Code != http.StatusOK {
		t.Fatalf("project page = %d (body %q)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `href="`+envPath(env)+`"`) {
		t.Error("the project page does not link to its environment")
	}
	if !strings.Contains(body, `action="/ui/projects/`+testProjectSlug+`/environments"`) {
		t.Error("the project page has no form to create an environment")
	}
	if !strings.Contains(body, `action="`+envPath(env)+`/delete"`) {
		t.Error("the project page has no form to delete the environment")
	}

	// 存在しない project は 404。
	if w := f.get(t, "/ui/projects/nosuchproject"); w.Code != http.StatusNotFound {
		t.Errorf("unknown project = %d, want 404", w.Code)
	}
	// 版の指定が不正な reveal は 400(パス変数をそのまま信用しない)。
	for _, version := range []string{"abc", "0", "-1"} {
		p := envPath(env) + "/items/DATABASE_URL/history/" + version + "/reveal"
		if w := f.post(t, p, nil); w.Code != http.StatusBadRequest {
			t.Errorf("reveal version %q = %d, want 400", version, w.Code)
		}
	}
	// 存在しない版は 404。
	if w := f.post(t, envPath(env)+"/items/DATABASE_URL/history/99/reveal", nil); w.Code != http.StatusNotFound {
		t.Errorf("reveal of a missing version = %d, want 404", w.Code)
	}

	// environment を論理削除する。
	w = f.post(t, envPath(env)+"/delete", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete environment = %d (body %q)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/ui/projects/"+testProjectSlug {
		t.Errorf("redirected to %q, want the project page", got)
	}
	if w := f.get(t, "/ui/projects/"+testProjectSlug); strings.Contains(w.Body.String(), `href="`+envPath(env)+`"`) {
		t.Error("the deleted environment is still listed")
	}
	// **配下の item へ到達できない。** 一覧も reveal も 404 になる。
	if w := f.get(t, envPath(env)); w.Code != http.StatusNotFound {
		t.Errorf("the environment of a deleted environment = %d, want 404", w.Code)
	}
	if w := f.post(t, envPath(env)+"/items/DATABASE_URL/reveal", nil); w.Code != http.StatusNotFound {
		t.Errorf("reveal under a deleted environment = %d, want 404", w.Code)
	}

	// project も論理削除する。
	if w := f.post(t, "/ui/projects/"+testProjectSlug+"/delete", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("delete project = %d", w.Code)
	}
	if w := f.get(t, "/ui/"); strings.Contains(w.Body.String(), `href="/ui/projects/`+testProjectSlug+`"`) {
		t.Error("the deleted project is still listed on the dashboard")
	}
	if w := f.get(t, "/ui/projects/"+testProjectSlug); w.Code != http.StatusNotFound {
		t.Errorf("a deleted project = %d, want 404", w.Code)
	}
	// 二重削除は 400(既に deleted_at が入っている行は更新されない)。
	if w := f.post(t, "/ui/projects/"+testProjectSlug+"/delete", nil); w.Code != http.StatusBadRequest {
		t.Errorf("deleting twice = %d, want 400", w.Code)
	}
}

// ---- マスク(AGENTS.md ルール 41、M5 完了条件) ----

// **どの一覧画面のレスポンスにも平文が現れない。**
//
// 「表示上マスクされている」ではなく **サーバーが値を返さない** ことが
// 要件である。テンプレートの見た目ではなく、**HTTP レスポンスのバイト列**
// を検査する。
func TestUIPagesNeverContainPlaintext(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)

	// 2 版目を書いて履歴を作る。
	updated := "postgres://user:" + "second@localhost/db"
	if w := f.post(t, envPath(env)+"/items/DATABASE_URL", url.Values{"value": {updated}}); w.Code != http.StatusSeeOther {
		t.Fatalf("update item = %d", w.Code)
	}
	// machine と grant、最終認証時刻(*time.Time の描画経路)も用意する。
	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}
	if w := f.post(t, "/ui/machines/1/grants",
		url.Values{"environment_id": {itoa(env.EnvironmentID)}}); w.Code != http.StatusSeeOther {
		t.Fatalf("create grant = %d", w.Code)
	}
	if _, err := f.store.DB().ExecContext(t.Context(),
		`UPDATE machines SET last_auth_at = ? WHERE id = 1`, vaultNow.Unix()); err != nil {
		t.Fatalf("set last_auth_at: %v", err)
	}

	pages := []string{
		"/ui/",
		"/ui/projects/" + testProjectSlug,
		envPath(env),
		envPath(env) + "/items/DATABASE_URL/history",
		"/ui/machines",
		"/ui/users",
		"/ui/audit",
	}
	for _, path := range pages {
		t.Run(path, func(t *testing.T) {
			w := f.get(t, path)
			if w.Code != http.StatusOK {
				t.Fatalf("%s = %d, want 200 (body %q)", path, w.Code, w.Body.String())
			}
			body := w.Body.String()
			for _, plaintext := range []string{testSecretValue, updated} {
				if strings.Contains(body, plaintext) {
					t.Errorf("%s contains a secret value", path)
				}
			}
			// **通常のページは reload**(平文ページと取り違えていない)。
			assertBFCacheReload(t, body)
			// credential 表示ブロックも出ない。
			if strings.Contains(body, `class="credential"`) {
				t.Errorf("%s renders a credential block", path)
			}
		})
	}
}

// ---- 無効化(緊急遮断操作) ----

// **machine とユーザーを画面から無効化できる。**
//
// ルートが存在しても、**フォームが描画されていなければ侵害時に遮断できない。**
// CSRF 拒否のテストではこの壊れ方を検出できない。
func TestUIDisableMachineAndUser(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}
	body := f.get(t, "/ui/machines").Body.String()
	if !strings.Contains(body, `action="/ui/machines/1/disable"`) {
		t.Fatal("the machine list has no form to disable the machine")
	}

	if w := f.post(t, "/ui/machines/1/disable", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("disable machine = %d (body %q)", w.Code, w.Body.String())
	}
	body = f.get(t, "/ui/machines").Body.String()
	if !strings.Contains(body, "無効") {
		t.Error("the machine list does not show the disabled state")
	}
	// 無効化済みには無効化フォームを出さない(二度押しの 400 を招かない)。
	if strings.Contains(body, `action="/ui/machines/1/disable"`) {
		t.Error("the disable form is still rendered for a disabled machine")
	}
	// **credential 再発行は残る**(無効化後に払い出し直す運用があるため)。
	if !strings.Contains(body, `action="/ui/machines/1/rotate"`) {
		t.Error("the rotate form disappeared")
	}
	var disabled int
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT disabled FROM machines WHERE id = 1`).Scan(&disabled); err != nil {
		t.Fatalf("select machine: %v", err)
	}
	if disabled != 1 {
		t.Error("the machine row is not disabled")
	}

	// パス変数が数値でない / 0 以下なら 400(ID として解釈しない)。
	for _, id := range []string{"abc", "0", "-1"} {
		if w := f.post(t, "/ui/machines/"+id+"/disable", nil); w.Code != http.StatusBadRequest {
			t.Errorf("disable machine %q = %d, want 400", id, w.Code)
		}
	}

	// **ユーザー無効化はセッションも消す**(ルール 53)。
	other := newTestUserNamed(t, f.store, "operator")
	otherSession := newTestSession(t, f.store, other)
	if w := f.post(t, "/ui/users/"+itoa(other)+"/disable", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("disable user = %d (body %q)", w.Code, w.Body.String())
	}
	if _, err := LookupSession(t.Context(), f.store.DB(), otherSession, vaultNow); err == nil {
		t.Error("the disabled user still has a valid session")
	}
	body = f.get(t, "/ui/users").Body.String()
	if !strings.Contains(body, "operator") {
		t.Error("the user list does not show the user (users are never deleted)")
	}
	if strings.Contains(body, `action="/ui/users/`+itoa(other)+`/disable"`) {
		t.Error("the disable form is still rendered for a disabled user")
	}
	// 自分自身の無効化フォームは描画しない(押せば 400 になるため)。
	if strings.Contains(body, `action="/ui/users/`+itoa(f.userID)+`/disable"`) {
		t.Error("the user list renders a form to disable yourself")
	}
}

// ---- 監査の fail closed(THREAT_MODEL §10.4) ----

// **secret の書き込み・表示・削除は、監査を記録できなければ実行しない。**
//
// 特に reveal は「記録に成功してから平文を返す」契約である。ここが
// fail open に倒れると、**監査に残らない平文の持ち出しが可能になる。**
func TestUISecretOperationsFailClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "API_TOKEN", testSecretValue)

	breakAuditTable(t, f.store)

	// 書き込み: 版が増えない(トランザクションごと巻き戻る)。
	if w := f.post(t, envPath(env)+"/items/API_TOKEN",
		url.Values{"value": {"another-value"}}); w.Code == http.StatusSeeOther {
		t.Error("the write succeeded while the audit log was broken")
	}
	var versions int
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM item_versions`).Scan(&versions); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if versions != 1 {
		t.Errorf("%d item versions, want 1 (the write must roll back)", versions)
	}

	// 表示: 平文を返さない。
	w := f.post(t, envPath(env)+"/items/API_TOKEN/reveal", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("reveal = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), testSecretValue) {
		t.Error("the plaintext was returned even though the audit record failed")
	}

	// 削除: 論理削除されない。
	if w := f.post(t, envPath(env)+"/items/API_TOKEN/delete", nil); w.Code == http.StatusSeeOther {
		t.Error("the delete succeeded while the audit log was broken")
	}
	var deleted sql.NullInt64
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT deleted_at FROM items WHERE key = 'API_TOKEN'`).Scan(&deleted); err != nil {
		t.Fatalf("select item: %v", err)
	}
	if deleted.Valid {
		t.Error("the item was marked deleted even though the audit record failed")
	}
}

// **grant の追加・削除が画面から実行できること。**
//
// grant 削除は「セキュリティを上げる緊急遮断操作」(AGENTS.md ルール 27)で
// ある。ルートが存在しても **フォームが描画されていなければ、侵害された
// machine の権限剥奪が UI 上で不可能** になる。
//
// CSRF 拒否のテストだけでは、この壊れ方を検出できない(ルートは存在するため)。
func TestUIGrantManagement(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	f.seedSecret(t, "API_TOKEN", testSecretValue)

	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}

	// 一覧に grant 追加フォーム(environment のプルダウン)が描画されていること。
	w := f.get(t, "/ui/machines")
	body := w.Body.String()
	if !strings.Contains(body, `action="/ui/machines/1/grants"`) {
		t.Fatal("the machine list has no form to add a grant")
	}
	if !strings.Contains(body, `name="environment_id"`) {
		t.Fatal("the grant form has no environment dropdown")
	}
	// **CSRF トークンが URL に入っていないこと。**
	if strings.Contains(body, "/ui/machines/"+f.csrf) {
		t.Fatal("the csrf token is rendered into a url")
	}

	// 追加できること。
	env, err := ResolveEnvironment(t.Context(), f.store.DB(), testProjectSlug, testEnvSlug)
	if err != nil {
		t.Fatalf("ResolveEnvironment: %v", err)
	}
	if w := f.post(t, "/ui/machines/1/grants",
		url.Values{"environment_id": {itoa(env.EnvironmentID)}}); w.Code != http.StatusSeeOther {
		t.Fatalf("create grant = %d (body %q)", w.Code, w.Body.String())
	}

	// 一覧に grant と、その削除フォームが出ること。
	w = f.get(t, "/ui/machines")
	body = w.Body.String()
	if !strings.Contains(body, testProjectSlug+"/"+testEnvSlug) {
		t.Error("the granted environment is not listed")
	}
	deletePath := "/ui/machines/1/grants/" + itoa(env.EnvironmentID) + "/delete"
	if !strings.Contains(body, `action="`+deletePath+`"`) {
		t.Fatalf("the machine list has no form to delete the grant (want %q)", deletePath)
	}

	// 削除できること。
	if w := f.post(t, deletePath, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("delete grant = %d (body %q)", w.Code, w.Body.String())
	}
	granted, err := HasGrant(t.Context(), f.store.DB(), 1, env.EnvironmentID)
	if err != nil {
		t.Fatalf("HasGrant: %v", err)
	}
	if granted {
		t.Error("the grant was not deleted")
	}
}

// **Web UI の unseal もレート制限される**(DESIGN §7.4 は socket と Web を
// まとめて「グローバル 3 回/分」と規定している)。
//
// 1 回ごとに argon2(64 MB)が走るので、連打で semaphore を占有され、正規の
// unseal やログインが詰まる。監査も fail closed で毎回書かれる。
func TestUIUnsealIsRateLimited(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	wrong := EncodeMasterKey(flipByte(f.mk, 0))

	for i := range unsealRate {
		if w := f.post(t, "/ui/unseal", url.Values{"master_key": {wrong}}); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	if w := f.post(t, "/ui/unseal", url.Values{"master_key": {wrong}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", unsealRate+1, w.Code)
	}
	// 正しいキーでも制限は同じ(グローバルであり、キーで分けていない)。
	if w := f.post(t, "/ui/unseal", url.Values{"master_key": {EncodeMasterKey(f.mk)}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a valid key bypassed the rate limit: %d", w.Code)
	}
}

// **Web からの unseal は actor を残す。**
//
// DESIGN §5.5 の anonymous は「攻撃者制御の生文字列を記録しない」ための規定で
// あって、認証済みリクエストの actor を消す規定ではない。捨てると「誰が本番を
// unseal したか」が監査ログから消える(THREAT_MODEL §10.1)。
func TestUIUnsealRecordsTheActor(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	if w := f.post(t, "/ui/unseal", url.Values{"master_key": {EncodeMasterKey(f.mk)}}); w.Code != http.StatusSeeOther {
		t.Fatalf("unseal = %d", w.Code)
	}

	var (
		actor  string
		userID sql.NullInt64
		detail string
	)
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT actor, actor_user_id, COALESCE(detail, '') FROM audit_logs
		WHERE action = ? AND result = ?`,
		string(ActionUnsealAttempt), string(ResultSuccess)).Scan(&actor, &userID, &detail); err != nil {
		t.Fatalf("select audit row: %v", err)
	}

	if want := actorUser(f.userID); actor != want {
		t.Errorf("actor = %q, want %q", actor, want)
	}
	if !userID.Valid || userID.Int64 != f.userID {
		t.Errorf("actor_user_id = %v, want %d", userID, f.userID)
	}
	if !strings.Contains(detail, ViaWeb) {
		t.Errorf("detail = %q, want via=web", detail)
	}
}

// エラー画面に内部のエラー文字列を出さない(renderError の契約)。
func TestUIErrorPagesDoNotLeakInternals(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	// 同じ slug の project を 2 回作る(2 回目は UNIQUE 制約で失敗する)。
	if w := f.post(t, "/ui/projects", url.Values{"slug": {"myapp"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("create project = %d", w.Code)
	}
	w := f.post(t, "/ui/projects", url.Values{"slug": {"myapp"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate project = %d, want 400", w.Code)
	}

	body := w.Body.String()
	for _, leak := range []string{"UNIQUE", "constraint", "SQL", "sqlite", "INSERT"} {
		if strings.Contains(body, leak) {
			t.Errorf("the error page leaks %q: %q", leak, body)
		}
	}
}

// **unseal のレート制限は admin socket と Web UI で共有される**(DESIGN §7.4)。
//
// 設計表の制限は経路ごとではなく「unseal(socket / Web) 3 回/分 グローバル」
// である。**別々のインスタンスを持つと、片方を上限まで叩きながらもう片方も
// 叩ける**(= 実効は 2 倍)。1 回ごとに argon2(64 MB)が走るため、そこが
// semaphore を占有する経路になる。
//
// このテストは形式不正のマスターキーで枠を消費する。**制限の判定は復号より
// 前にある**ので argon2 は走らず、共有そのものだけを見られる。
func TestUnsealRateLimitIsSharedWithTheAdminSocket(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	// **同じ limiter を渡す**(cmd_serve.go の startListeners と同じ配線)。
	a := newAdminServer(f.vault, discardLogger(), f.ui.unsealLimiter)
	a.now = func() time.Time { return vaultNow }

	const malformed = "not-a-master-key"

	// socket 側で 2 回消費する。
	for i := range 2 {
		if w := doAdmin(t, a, http.MethodPost, "/unseal", []byte(malformed)); w.Code != http.StatusBadRequest {
			t.Fatalf("socket attempt %d = %d, want 400", i+1, w.Code)
		}
	}
	// Web 側で 3 回目を消費する。
	if w := f.post(t, "/ui/unseal", url.Values{"master_key": {malformed}}); w.Code != http.StatusBadRequest {
		t.Fatalf("web attempt 3 = %d, want 400", w.Code)
	}

	// **4 回目はどちらの経路でも 429。**
	if w := f.post(t, "/ui/unseal", url.Values{"master_key": {EncodeMasterKey(f.mk)}}); w.Code != http.StatusTooManyRequests {
		t.Errorf("web attempt 4 = %d, want 429 (the limiter is not shared)", w.Code)
	}
	if w := doAdmin(t, a, http.MethodPost, "/unseal", []byte(EncodeMasterKey(f.mk))); w.Code != http.StatusTooManyRequests {
		t.Errorf("socket attempt 4 = %d, want 429 (the limiter is not shared)", w.Code)
	}
	// 制限に掛かった間は vault が開いていないこと。
	if f.vault.Status().State != StateSealed {
		t.Error("the vault was unsealed despite the rate limit")
	}
}

// **ログインの第一段は送信元 IP である**(AGENTS.md ルール 35、DESIGN §7.4)。
//
// username だけを鍵にすると、攻撃者は username を変えるだけで無制限に
// 試行できる。逆に IP だけだと、1 つの username に対する総当たりを
// 分散されたときに止まらない。**二段構えになっていること**を見る。
//
// 上限は fixture 側で小さくする。既定値(IP 20 / username 5)で回すと、
// 失敗ログインのたびに dummy argon2(64 MB)が走って高くつく。
func TestUILoginIsRateLimitedByIPFirst(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)

	attempt := func(username, remoteAddr string) int {
		form := url.Values{"username": {username}, "password": {"wrong-password"}}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ui/login",
			strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Host = "hokora.internal:8443"
		r.RemoteAddr = remoteAddr

		w := httptest.NewRecorder()
		withUIHeaders(f.ui.uiMux()).ServeHTTP(w, r)
		return w.Code
	}

	// 第一段(IP)。**username を変えても素通りしない。**
	f.ipLimits(1, 100)
	if got := attempt(testUsername, "10.8.0.9:51234"); got != http.StatusUnauthorized {
		t.Fatalf("the first attempt = %d, want 401", got)
	}
	if got := attempt("someone-else", "10.8.0.9:40000"); got != http.StatusTooManyRequests {
		t.Errorf("a second attempt from the same ip = %d, want 429 (changing the username bypassed the limit)", got)
	}

	// 第二段(username)。**IP を変えても素通りしない。**
	f.ipLimits(100, 1)
	if got := attempt(testUsername, "10.8.0.10:51234"); got != http.StatusUnauthorized {
		t.Fatalf("the first attempt for the username = %d, want 401", got)
	}
	if got := attempt(testUsername, "10.8.0.11:51234"); got != http.StatusTooManyRequests {
		t.Errorf("the same username from another ip = %d, want 429", got)
	}
	// 別の username なら通る(username の枠は鍵ごとである)。
	if got := attempt("someone-else", "10.8.0.12:51234"); got != http.StatusUnauthorized {
		t.Errorf("another username = %d, want 401", got)
	}
}

// ipLimits はログインのレート制限を差し替える(テスト用に小さくする)。
func (f *uiFixture) ipLimits(perIP, perUsername int) {
	f.ui.ipLimiter = newRateLimiter(perIP, 0)
	f.ui.usernameLimiter = newRateLimiter(perUsername, 0)
}

// C: 第二段(username)のレート制限に引っかかった試行も監査される
// (auth.user / failure / reason=rate_limited)。第一段(IP)は未認証トラフィック
// で監査 DB を膨らませないために記録しない ── ここでは第二段だけを見る。
// **生の username は subject_digest に潰す**(ルール 25)。
func TestUILoginUsernameRateLimitIsAudited(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.ipLimits(100, 1)

	attempt := func(username, remoteAddr string) int {
		form := url.Values{"username": {username}, "password": {"wrong-password"}}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ui/login",
			strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Host = "hokora.internal:8443"
		r.RemoteAddr = remoteAddr

		w := httptest.NewRecorder()
		withUIHeaders(f.ui.uiMux()).ServeHTTP(w, r)
		return w.Code
	}

	// 1 回目は Login() 自身が invalid_credentials で監査する(通常のログイン
	// 失敗)。2 回目で username の枠を使い切り、rate_limited が記録される。
	if got := attempt(testUsername, "10.8.0.20:51234"); got != http.StatusUnauthorized {
		t.Fatalf("the first attempt = %d, want 401", got)
	}
	if got := attempt(testUsername, "10.8.0.21:51234"); got != http.StatusTooManyRequests {
		t.Fatalf("the second attempt (same username, another ip) = %d, want 429", got)
	}

	// **直近の行を見る。** 1 回目の invalid_credentials 行と混同しないため。
	var actor, detail string
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT actor, COALESCE(detail, '') FROM audit_logs
		WHERE action = ? AND result = ?
		ORDER BY id DESC LIMIT 1`,
		string(ActionAuthUser), string(ResultFailure)).Scan(&actor, &detail); err != nil {
		t.Fatalf("select audit row: %v", err)
	}

	if actor != ActorAnonymous {
		t.Errorf("actor = %q, want %q", actor, ActorAnonymous)
	}
	if !strings.Contains(detail, `"reason":"`+ReasonRateLimited+`"`) {
		t.Errorf("detail = %q, want reason = %q", detail, ReasonRateLimited)
	}
	if strings.Contains(detail, testUsername) {
		t.Errorf("detail contains the raw username: %q", detail)
	}
	if !strings.Contains(detail, subjectDigest(testUsername)) {
		t.Errorf("detail = %q, want it to contain the subject digest", detail)
	}
}
