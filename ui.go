package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// maxUIFormBody は Web UI のフォームの上限である(DESIGN §7.4)。
const maxUIFormBody = 128 << 10

// uiAuditLimit は監査ログ画面に出す件数である。
//
// **保持期間は無限**(Q4)なので、全件を描画しない。ページングは持たず、
// 直近のみを見せる(古い記録の調査は DB を直接見る運用)。
const uiAuditLimit = 200

// loginRate / usernameRate は Web UI ログインの制限である(DESIGN §7.4)。
// **第一段は送信元 IP**(AGENTS.md ルール 35)。
const (
	loginRatePerIP       = 20
	loginRatePerUsername = 5
)

// uiServer は Web UI(:8443、uiMux、VPN IF のみ)のハンドラである。
//
// **この mux は Machine API / admin socket とは共有しない**
// (AGENTS.md ルール 29)。
type uiServer struct {
	vault  *Vault
	logger *slog.Logger
	tmpl   map[string]*template.Template

	ipLimiter       *rateLimiter
	usernameLimiter *rateLimiter
	// unsealLimiter は admin socket と **共有する**(DESIGN §7.4 の制限は
	// 経路ごとではなくグローバルである)。
	unsealLimiter *rateLimiter

	now func() time.Time
}

func newUIServer(v *Vault, logger *slog.Logger, unsealLimiter *rateLimiter) (*uiServer, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &uiServer{
		vault:           v,
		logger:          logger,
		tmpl:            tmpl,
		ipLimiter:       newRateLimiter(loginRatePerIP, 0),
		usernameLimiter: newRateLimiter(loginRatePerUsername, 0),
		unsealLimiter:   unsealLimiter,
		now:             time.Now,
	}, nil
}

// uiMux は Web UI 専用の ServeMux を作る(DESIGN §8.3 のルーティング表)。
//
// ハンドラは 3 種類に分かれる:
//
//   - static: 認証不要(ログイン画面でも読み込むため)
//   - public: セッション不要(ログイン)
//   - authed: セッション必須。**sealed でも動くもの**(パスワード変更、unseal)と
//     **unsealed を要求するもの**(それ以外)がある
func (u *uiServer) uiMux() *http.ServeMux {
	mux := http.NewServeMux()

	// **静的アセットだけが認証不要である**(DESIGN §9.4)。
	mux.Handle("GET /ui/static/", http.StripPrefix("/ui/static/", u.staticHandler()))

	mux.HandleFunc("GET /ui/login", u.handleLoginForm)
	mux.HandleFunc("POST /ui/login", u.handleLogin)
	mux.HandleFunc("POST /ui/logout", u.authed(sealedOK, u.handleLogout))

	// **パスワード変更と unseal は sealed でも動く**(DESIGN §8.3)。
	// 初回セットアップ時は必ず sealed であり、ここで unsealed を要求すると
	// 初回ログインが詰む。
	mux.HandleFunc("GET /ui/password", u.authed(sealedOK, u.handlePasswordForm))
	mux.HandleFunc("POST /ui/password", u.authed(sealedOK, u.handlePasswordChange))
	mux.HandleFunc("GET /ui/unseal", u.authed(sealedOK, u.handleUnsealForm))
	mux.HandleFunc("POST /ui/unseal", u.authed(sealedOK, u.handleUnseal))

	mux.HandleFunc("GET /ui/{$}", u.authed(needUnsealed, u.handleDashboard))
	mux.HandleFunc("POST /ui/projects", u.authed(needUnsealed, u.handleCreateProject))
	mux.HandleFunc("GET /ui/projects/{slug}", u.authed(needUnsealed, u.handleProject))
	mux.HandleFunc("POST /ui/projects/{slug}/delete", u.authed(needUnsealed, u.handleDeleteProject))
	mux.HandleFunc("POST /ui/projects/{slug}/environments", u.authed(needUnsealed, u.handleCreateEnvironment))

	mux.HandleFunc("GET /ui/projects/{slug}/{env}", u.authed(needUnsealed, u.handleEnvironment))
	mux.HandleFunc("POST /ui/projects/{slug}/{env}/delete", u.authed(needUnsealed, u.handleDeleteEnvironment))
	mux.HandleFunc("POST /ui/projects/{slug}/{env}/machines", u.authed(needUnsealed, u.handleCreateMachineForEnv))
	mux.HandleFunc("POST /ui/projects/{slug}/{env}/items", u.authed(needUnsealed, u.handlePutItem))
	mux.HandleFunc("POST /ui/projects/{slug}/{env}/items/{key}", u.authed(needUnsealed, u.handlePutItem))
	mux.HandleFunc("POST /ui/projects/{slug}/{env}/items/{key}/reveal", u.authed(needUnsealed, u.handleReveal))
	mux.HandleFunc("POST /ui/projects/{slug}/{env}/items/{key}/delete", u.authed(needUnsealed, u.handleDeleteItem))
	mux.HandleFunc("GET /ui/projects/{slug}/{env}/items/{key}/history", u.authed(needUnsealed, u.handleHistory))
	mux.HandleFunc("POST /ui/projects/{slug}/{env}/items/{key}/history/{version}/reveal",
		u.authed(needUnsealed, u.handleRevealVersion))

	mux.HandleFunc("GET /ui/machines", u.authed(needUnsealed, u.handleMachines))
	mux.HandleFunc("POST /ui/machines", u.authed(needUnsealed, u.handleCreateMachine))
	mux.HandleFunc("POST /ui/machines/{id}/rotate", u.authed(needUnsealed, u.handleRotateMachine))
	mux.HandleFunc("POST /ui/machines/{id}/disable", u.authed(needUnsealed, u.handleDisableMachine))
	mux.HandleFunc("POST /ui/machines/{id}/grants", u.authed(needUnsealed, u.handleCreateGrant))
	mux.HandleFunc("POST /ui/machines/{id}/grants/{envID}/delete", u.authed(needUnsealed, u.handleDeleteGrant))

	mux.HandleFunc("GET /ui/users", u.authed(needUnsealed, u.handleUsers))
	mux.HandleFunc("POST /ui/users", u.authed(needUnsealed, u.handleCreateUser))
	mux.HandleFunc("POST /ui/users/{id}/disable", u.authed(needUnsealed, u.handleDisableUser))

	mux.HandleFunc("GET /ui/audit", u.authed(needUnsealed, u.handleAudit))

	return mux
}

// staticHandler は embed した静的アセットを配信する。
//
// **認証不要で配るのは static/ のみ**(DESIGN §9.4)。
func (u *uiServer) staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// embed の内容は起動時に確定しているので、ここが失敗するのは
		// ビルド構成の誤りである。
		panic("hokora: static assets are missing: " + err.Error())
	}
	return http.FileServerFS(sub)
}

// ---- ミドルウェア ----

// sealedMode は「sealed でも動くか」を表す。
type sealedMode int

const (
	// needUnsealed は unsealed を要求する。sealed なら /ui/unseal へ送る。
	needUnsealed sealedMode = iota
	// sealedOK は sealed でも動く(パスワード変更、unseal、logout)。
	sealedOK
)

// uiRequest は認証済みリクエストの文脈である。
type uiRequest struct {
	User     *SessionUser
	RawToken []byte
	Now      time.Time
}

// remoteAddr は監査に載せる送信元である。
func (r uiRequest) auditCtx() auditCtx {
	return auditCtx{
		Actor:       actorUser(r.User.UserID),
		ActorUserID: &r.User.UserID,
		Via:         ViaWeb,
		Now:         r.Now,
	}
}

type uiHandler func(w http.ResponseWriter, r *http.Request, req uiRequest)

// authed はセッション検証・CSRF 検証・sealed 判定をまとめて行う。
//
// **各ハンドラが個別に呼ぶのではなく、ルーティングの時点で被せる。**
// ハンドラ側で「認証を確認する」ことを忘れられる形にしない。
func (u *uiServer) authed(mode sealedMode, next uiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := u.now()

		raw, err := sessionTokenFromRequest(r)
		if err != nil {
			u.redirectToLogin(w, r)
			return
		}
		defer Zero(raw)

		// **絶対期限と idle 期限、ユーザーの disabled を毎回検査する**
		// (AGENTS.md ルール 51-52)。
		su, err := LookupSession(r.Context(), u.vault.db, raw, now)
		if err != nil {
			clearSessionCookie(w)
			u.redirectToLogin(w, r)
			return
		}

		// **POST は CSRF トークンを検証する**(DESIGN §7.3)。
		if r.Method == http.MethodPost {
			if err := u.parseForm(w, r); err != nil {
				u.renderError(w, r, http.StatusBadRequest, "フォームを読み取れませんでした")
				return
			}
			if err := verifyCSRF(raw, r.PostFormValue("csrf_token")); err != nil {
				// **認証済みの主体が拒否された事実を記録する**(ルール 22/26)。
				// actor はセッションの user。fail open(拒否はどのみち確定して
				// いるので、記録できなくても 403 のまま)。
				reason := ReasonInvalidCSRF
				ac := auditCtx{Actor: actorUser(su.UserID), ActorUserID: &su.UserID, Via: ViaWeb, Now: now}
				RecordAuditBestEffort(r.Context(), u.vault.db, u.logger,
					ac.entry(ActionCSRFReject, ResultFailure, &AuditDetail{Reason: &reason}))
				u.renderError(w, r, http.StatusForbidden, "セッションが切り替わりました。操作をやり直してください")
				return
			}
		}

		req := uiRequest{User: su, RawToken: raw, Now: now}

		// **must_change_pw ならパスワード変更へ送る**(DESIGN §8.3 の初回フロー)。
		if su.MustChangePW && !isPasswordRoute(r) && !isLogoutRoute(r) {
			http.Redirect(w, r, "/ui/password", http.StatusSeeOther)
			return
		}

		if mode == needUnsealed && u.vault.Status().State != StateUnsealed {
			http.Redirect(w, r, "/ui/unseal", http.StatusSeeOther)
			return
		}

		next(w, r, req)
	}
}

func isPasswordRoute(r *http.Request) bool { return r.URL.Path == "/ui/password" }
func isLogoutRoute(r *http.Request) bool   { return r.URL.Path == "/ui/logout" }

// redirectToSlug は project / environment のページへ戻す。
//
// **リダイレクト先は検証済みの slug からのみ組み立てる。** slug は
// `^[a-z0-9][a-z0-9-]{0,63}$` に限られるので "//evil.example" のような
// 相対 URL にはならないが、**その保証をリダイレクトの直前に置く**
// (作成関数が検証していることに依存すると、経路が増えたときに崩れる)。
func (u *uiServer) redirectToSlug(w http.ResponseWriter, r *http.Request, projectSlug, envSlug string) {
	if ValidateSlug(projectSlug) != nil || (envSlug != "" && ValidateSlug(envSlug) != nil) {
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
		return
	}
	path := "/ui/projects/" + projectSlug
	if envSlug != "" {
		path += "/" + envSlug
	}
	// 直前で ValidateSlug を通しており、"//" や ":" を含む値は到達しない。
	http.Redirect(w, r, path, http.StatusSeeOther) //nolint:gosec // G710: 検証済みの slug から組み立てている
}

func (u *uiServer) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// **戻り先を引き継がない。** クエリに任意の URL を載せると、そこが
	// オープンリダイレクトの入口になる。
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

// parseForm はボディを上限つきで読み、フォームとして解釈する。
func (u *uiServer) parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxUIFormBody)
	return r.ParseForm()
}

// ---- ログイン ----

func (u *uiServer) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	u.render(w, r, "login.html", pageData{Title: "ログイン"})
}

func (u *uiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	now := u.now()
	remote := remoteIP(r)

	// **pre-auth の CSRF 対策は Fetch Metadata / Origin である**(DESIGN §7.3)。
	// セッションがまだ無いので CSRF トークンを使えない。
	if err := checkFetchMetadata(r); err != nil {
		u.renderError(w, r, http.StatusForbidden, "リクエストの発行元を確認できませんでした")
		return
	}

	// 第一段: 送信元 IP。**攻撃者が変えられない値を先に置く。**
	if !u.ipLimiter.Allow(remote, now) {
		u.renderError(w, r, http.StatusTooManyRequests, "試行が多すぎます。しばらく待ってください")
		return
	}
	if err := u.parseForm(w, r); err != nil {
		u.renderError(w, r, http.StatusBadRequest, "フォームを読み取れませんでした")
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	// 第二段: username。攻撃者制御の値なので、これ *だけ* には頼らない。
	if !u.usernameLimiter.Allow(username, now) {
		// **第二段の拒否は記録する**(Machine API の client_id 段と対称)。
		// 第一段(IP)は記録しない ── 未認証トラフィックで監査を膨らませない
		// ため。生の username は subject_digest に潰す(ルール 25)。fail open。
		digest := subjectDigest(username)
		reason := ReasonRateLimited
		ac := anonymousAudit(remote, now)
		RecordAuditBestEffort(r.Context(), u.vault.db, u.logger,
			ac.entry(ActionAuthUser, ResultFailure, &AuditDetail{Reason: &reason, SubjectDigest: &digest}))
		u.renderError(w, r, http.StatusTooManyRequests, "試行が多すぎます。しばらく待ってください")
		return
	}

	res, err := Login(r.Context(), u.vault.db, username, password, remote, now)
	if err != nil {
		if !errors.Is(err, ErrInvalidCredentials) {
			u.internalError(w, r, "login", err)
			return
		}
		// **どちらが違うかを言わない。**
		u.renderStatus(w, r, http.StatusUnauthorized, "login.html", pageData{
			Title: "ログイン",
			Error: "ユーザー名またはパスワードが違います",
		})
		return
	}

	// **ログイン成功時にセッション ID を再生成する**(ルール 45)。
	// Login が毎回新しいトークンを作るので、ここで張り替えれば足りる。
	setSessionCookie(w, res.Token)

	if res.MustChangePW {
		http.Redirect(w, r, "/ui/password", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

func (u *uiServer) handleLogout(w http.ResponseWriter, r *http.Request, req uiRequest) {
	if err := Logout(r.Context(), u.vault.db, u.logger, req.User.UserID, req.RawToken, req.auditCtx()); err != nil {
		u.internalError(w, r, "logout", err)
		return
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

// ---- パスワード変更 ----

func (u *uiServer) handlePasswordForm(w http.ResponseWriter, r *http.Request, req uiRequest) {
	u.render(w, r, "password.html", u.page(req, "パスワード変更"))
}

func (u *uiServer) handlePasswordChange(w http.ResponseWriter, r *http.Request, req uiRequest) {
	current := r.PostFormValue("current_password")
	next := r.PostFormValue("new_password")
	confirm := r.PostFormValue("confirm_password")

	if next != confirm {
		u.renderStatus(w, r, http.StatusBadRequest, "password.html",
			u.pageWithError(req, "パスワード変更", "新しいパスワードが一致しません"))
		return
	}
	if err := ValidatePassword(next); err != nil {
		reason := userFacingReason(err)
		if reason == "" {
			reason = "パスワードを変更できませんでした"
		}
		u.renderStatus(w, r, http.StatusBadRequest, "password.html",
			u.pageWithError(req, "パスワード変更", reason))
		return
	}

	token, err := ChangePassword(r.Context(), u.vault.db, u.logger, req.User.UserID,
		current, next, req.auditCtx())
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			u.renderStatus(w, r, http.StatusUnauthorized, "password.html",
				u.pageWithError(req, "パスワード変更", "現在のパスワードが違います"))
			return
		}
		reason := userFacingReason(err)
		if reason == "" {
			reason = "パスワードを変更できませんでした"
		}
		u.renderStatus(w, r, http.StatusBadRequest, "password.html",
			u.pageWithError(req, "パスワード変更", reason))
		return
	}

	// **セッションを張り替える**(全セッションが消えているため)。
	setSessionCookie(w, token)

	// sealed なら unseal へ、unsealed ならダッシュボードへ(DESIGN §8.3)。
	if u.vault.Status().State != StateUnsealed {
		http.Redirect(w, r, "/ui/unseal", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

// ---- unseal ----

func (u *uiServer) handleUnsealForm(w http.ResponseWriter, r *http.Request, req uiRequest) {
	if u.vault.Status().State == StateUnsealed {
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
		return
	}
	u.render(w, r, "unseal.html", u.page(req, "unseal"))
}

func (u *uiServer) handleUnseal(w http.ResponseWriter, r *http.Request, req uiRequest) {
	// **レート制限は socket と共有のグローバル制限である**(DESIGN §7.4)。
	// 1 回ごとに argon2(64 MB)が走るので、連打で semaphore を占有され、
	// 正規の unseal やログインが詰まる。監査も fail closed で毎回書かれるため、
	// 削除できない監査テーブルを膨らませる口にもなる。
	if !u.unsealLimiter.Allow(globalKey, u.now()) {
		u.renderStatus(w, r, http.StatusTooManyRequests, "unseal.html",
			u.pageWithError(req, "unseal", "試行が多すぎます。しばらく待ってください"))
		return
	}

	// **MK は HTTP リクエストボディからのみ受け取る**(AGENTS.md ルール 12)。
	//
	// ここで Zero するのはコピーしたバイト列だけである。**ParseForm が作った
	// r.PostForm の string は不変で、ゼロクリアできない。** admin socket 側は
	// 生ボディを読んで消すので、そちらの方が保証は強い。mlockall により
	// ディスクへは出ないため受容する(DESIGN §6.6 の best effort と同じ扱い)。
	body := []byte(r.PostFormValue("master_key"))
	defer Zero(body)

	mk, err := DecodeMasterKey(body)
	if err != nil {
		u.renderStatus(w, r, http.StatusBadRequest, "unseal.html",
			u.pageWithError(req, "unseal", "マスターキーの形式が正しくありません"))
		return
	}
	defer Zero(mk)

	// **actor は残す。** DESIGN §5.5 の anonymous は「存在しない username /
	// client_id での認証失敗」= 攻撃者制御の生文字列を記録しないための規定で
	// あって、認証済みリクエストの actor を消す規定ではない。ここで捨てると
	// 「誰が本番を unseal したか」が監査ログから消える(THREAT_MODEL §10.1)。
	// socket 経路が anonymous なのは、そこに identity が無いためである。
	ac := req.auditCtx()
	remote := remoteIP(r)
	ac.RemoteAddr = &remote

	switch err := u.vault.Unseal(r.Context(), mk, ac); {
	case err == nil, errors.Is(err, ErrAlreadyUnsealed):
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
	case errors.Is(err, ErrDecrypt):
		u.renderStatus(w, r, http.StatusUnauthorized, "unseal.html",
			u.pageWithError(req, "unseal", "マスターキーが違います"))
	default:
		u.internalError(w, r, "unseal", err)
	}
}

// ---- project / environment ----

func (u *uiServer) handleDashboard(w http.ResponseWriter, r *http.Request, req uiRequest) {
	projects, err := ListProjects(r.Context(), u.vault.db)
	if err != nil {
		u.internalError(w, r, "list projects", err)
		return
	}
	data := u.page(req, "プロジェクト")
	data.Projects = projects
	u.render(w, r, "dashboard.html", data)
}

func (u *uiServer) handleCreateProject(w http.ResponseWriter, r *http.Request, req uiRequest) {
	slug := r.PostFormValue("slug")
	if _, err := CreateProject(r.Context(), u.vault.db, slug, r.PostFormValue("name"), req.auditCtx()); err != nil {
		u.badRequest(w, r, "プロジェクトを作成できませんでした", err)
		return
	}
	u.redirectToSlug(w, r, slug, "")
}

func (u *uiServer) handleProject(w http.ResponseWriter, r *http.Request, req uiRequest) {
	p, err := FindProject(r.Context(), u.vault.db, r.PathValue("slug"))
	if errors.Is(err, ErrNotFound) {
		u.renderError(w, r, http.StatusNotFound, "プロジェクトが見つかりません")
		return
	}
	if err != nil {
		u.internalError(w, r, "find project", err)
		return
	}

	envs, err := ListEnvironments(r.Context(), u.vault.db, p.ID)
	if err != nil {
		u.internalError(w, r, "list environments", err)
		return
	}

	data := u.page(req, p.Slug)
	data.Project = p
	data.Environments = envs
	u.render(w, r, "project.html", data)
}

func (u *uiServer) handleDeleteProject(w http.ResponseWriter, r *http.Request, req uiRequest) {
	if err := DeleteProject(r.Context(), u.vault.db, r.PathValue("slug"), req.auditCtx()); err != nil {
		u.badRequest(w, r, "プロジェクトを削除できませんでした", err)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

func (u *uiServer) handleCreateEnvironment(w http.ResponseWriter, r *http.Request, req uiRequest) {
	slug := r.PathValue("slug")
	env := r.PostFormValue("slug")
	if _, err := CreateEnvironment(r.Context(), u.vault.db, slug, env, r.PostFormValue("name"), req.auditCtx()); err != nil {
		u.badRequest(w, r, "環境を作成できませんでした", err)
		return
	}
	u.redirectToSlug(w, r, slug, env)
}

func (u *uiServer) handleEnvironment(w http.ResponseWriter, r *http.Request, req uiRequest) {
	env, ok := u.resolveEnv(w, r)
	if !ok {
		return
	}
	u.renderEnvironment(w, r, req, env, nil)
}

// renderEnvironment は environment のページを描く。credential が非 nil なら、
// この環境向けに作成したサーバーの credential を**一度だけ**表示する(#9)。
func (u *uiServer) renderEnvironment(w http.ResponseWriter, r *http.Request, req uiRequest, env *EnvironmentRef, credential *machineCredential) {
	// **一覧は平文を返さない**(AGENTS.md ルール 41)。ItemRow に値が無い。
	items, err := ListItems(r.Context(), u.vault.db, env.EnvironmentID)
	if err != nil {
		u.internalError(w, r, "list items", err)
		return
	}

	data := u.page(req, env.ProjectSlug+"/"+env.EnvSlug)
	data.Env = env
	data.Items = items
	data.Credential = credential
	if credential != nil {
		// **credential も平文である**(AGENTS.md ルール 50)。作成導線でも
		// reveal / machines と同等に、GET な安全 URL へ退避する。
		data.BFCache = "replace"
		data.BFCacheURL = envPath(env)
	}
	u.render(w, r, "environment.html", data)
}

// handleCreateMachineForEnv は environment 画面から、この環境へのアクセス権を
// 持つサーバーを作成する(#9)。作成とアクセス権付与は 1 トランザクション。
func (u *uiServer) handleCreateMachineForEnv(w http.ResponseWriter, r *http.Request, req uiRequest) {
	env, ok := u.resolveEnv(w, r)
	if !ok {
		return
	}

	// **client_id はサーバーが生成する**(handleCreateMachine と同じ。ルール8)。
	clientID, err := GenerateClientID()
	if err != nil {
		u.internalError(w, r, "generate client id", err)
		return
	}

	_, secret, err := CreateMachineWithGrant(r.Context(), u.vault.db, clientID, r.PostFormValue("name"), env.EnvironmentID, req.auditCtx())
	if err != nil {
		u.badRequest(w, r, "サーバーを作成できませんでした", err)
		return
	}
	// **client_secret はここでしか表示されない**(machines と同じ。ルール50)。
	u.renderEnvironment(w, r, req, env, &machineCredential{ClientID: clientID, ClientSecret: secret})
}

func (u *uiServer) handleDeleteEnvironment(w http.ResponseWriter, r *http.Request, req uiRequest) {
	slug := r.PathValue("slug")
	if err := DeleteEnvironment(r.Context(), u.vault.db, slug, r.PathValue("env"), req.auditCtx()); err != nil {
		u.badRequest(w, r, "環境を削除できませんでした", err)
		return
	}
	u.redirectToSlug(w, r, slug, "")
}

// ---- item ----

func (u *uiServer) handlePutItem(w http.ResponseWriter, r *http.Request, req uiRequest) {
	env, ok := u.resolveEnv(w, r)
	if !ok {
		return
	}

	key := r.PathValue("key")
	if key == "" {
		key = r.PostFormValue("key")
	}
	value := []byte(r.PostFormValue("value"))
	defer Zero(value)

	if err := PutSecret(r.Context(), u.vault, env, key, value, req.auditCtx()); err != nil {
		u.badRequest(w, r, "保存できませんでした", err)
		return
	}
	u.redirectToEnv(w, r, env)
}

func (u *uiServer) handleDeleteItem(w http.ResponseWriter, r *http.Request, req uiRequest) {
	env, ok := u.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := DeleteItem(r.Context(), u.vault.db, env, r.PathValue("key"), req.auditCtx()); err != nil {
		u.badRequest(w, r, "削除できませんでした", err)
		return
	}
	u.redirectToEnv(w, r, env)
}

// handleReveal は現行版の平文を表示する。
//
// **平文を含むページである**(DESIGN §9.2)。bfcache 対策の対象なので、
// テンプレートに data-bfcache="replace" と退避先 URL を渡す。
func (u *uiServer) handleReveal(w http.ResponseWriter, r *http.Request, req uiRequest) {
	u.reveal(w, r, req, 0)
}

func (u *uiServer) handleRevealVersion(w http.ResponseWriter, r *http.Request, req uiRequest) {
	version, err := strconv.ParseInt(r.PathValue("version"), 10, 64)
	if err != nil || version <= 0 {
		u.renderError(w, r, http.StatusBadRequest, "バージョンの指定が不正です")
		return
	}
	u.reveal(w, r, req, version)
}

func (u *uiServer) reveal(w http.ResponseWriter, r *http.Request, req uiRequest, version int64) {
	env, ok := u.resolveEnv(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")

	// **監査を確定させてから平文が返る**(RevealSecret の契約)。
	value, err := RevealSecret(r.Context(), u.vault, env, key, version, req.auditCtx())
	if errors.Is(err, ErrNotFound) {
		u.renderError(w, r, http.StatusNotFound, "見つかりません")
		return
	}
	if err != nil {
		u.internalError(w, r, "reveal secret", err)
		return
	}

	data := u.page(req, key)
	data.Env = env
	data.Key = key
	data.Value = value
	data.Version = version
	// **平文ページは replace。** POST の結果なので reload は再送確認を招き、
	// キャンセルされると平文が残る(DESIGN §9.3)。
	data.BFCache = "replace"
	data.BFCacheURL = envPath(env)
	u.render(w, r, "reveal.html", data)
}

func (u *uiServer) handleHistory(w http.ResponseWriter, r *http.Request, req uiRequest) {
	env, ok := u.resolveEnv(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")

	item, err := FindItem(r.Context(), u.vault.db, env.EnvironmentID, key)
	if errors.Is(err, ErrNotFound) {
		u.renderError(w, r, http.StatusNotFound, "見つかりません")
		return
	}
	if err != nil {
		u.internalError(w, r, "find item", err)
		return
	}

	versions, err := ListItemVersions(r.Context(), u.vault.db, item.ID)
	if err != nil {
		u.internalError(w, r, "list versions", err)
		return
	}

	data := u.page(req, key+" の履歴")
	data.Env = env
	data.Key = key
	data.Versions = versions
	u.render(w, r, "history.html", data)
}

// ---- machine ----

func (u *uiServer) handleMachines(w http.ResponseWriter, r *http.Request, req uiRequest) {
	u.renderMachines(w, r, req, nil)
}

// renderMachines は Machine 一覧を描く。credential が非 nil なら、それを
// **一度だけ**表示する(DESIGN §9.2 の bfcache 対策対象)。
func (u *uiServer) renderMachines(w http.ResponseWriter, r *http.Request, req uiRequest, credential *machineCredential) {
	machines, err := ListMachines(r.Context(), u.vault.db)
	if err != nil {
		u.internalError(w, r, "list machines", err)
		return
	}
	grantable, err := ListGrantableEnvironments(r.Context(), u.vault.db)
	if err != nil {
		u.internalError(w, r, "list grantable environments", err)
		return
	}

	data := u.page(req, "サーバー")
	data.Machines = machines
	data.Grantable = grantable
	data.Credential = credential
	if credential != nil {
		// **credential も平文である**(AGENTS.md ルール 50)。
		data.BFCache = "replace"
		data.BFCacheURL = "/ui/machines"
	}
	u.render(w, r, "machines.html", data)
}

// machineCredential は一度だけ表示する credential である。
type machineCredential struct {
	ClientID     string
	ClientSecret string
	Rotated      bool
}

func (u *uiServer) handleCreateMachine(w http.ResponseWriter, r *http.Request, req uiRequest) {
	// **client_id はサーバーが生成する。** secret と違い公開値なので、
	// 命名の一貫性と重複回避のために自動生成する。
	clientID, err := GenerateClientID()
	if err != nil {
		u.internalError(w, r, "generate client id", err)
		return
	}

	_, secret, err := CreateMachine(r.Context(), u.vault.db, clientID, r.PostFormValue("name"), req.auditCtx())
	if err != nil {
		u.badRequest(w, r, "サーバーを作成できませんでした", err)
		return
	}
	// **client_secret はここでしか表示されない。** 保存されるのは
	// SHA-256 のハッシュだけである。client_id は作成時にのみ表示し、
	// 一覧には出さない(#7)。
	u.renderMachines(w, r, req, &machineCredential{ClientID: clientID, ClientSecret: secret})
}

func (u *uiServer) handleRotateMachine(w http.ResponseWriter, r *http.Request, req uiRequest) {
	id, ok := u.pathID(w, r, "id")
	if !ok {
		return
	}

	secret, err := RotateMachineSecret(r.Context(), u.vault, id, req.auditCtx())
	if err != nil {
		u.badRequest(w, r, "credential を再発行できませんでした", err)
		return
	}

	u.renderMachines(w, r, req, &machineCredential{ClientID: clientIDOf(r.Context(), u.vault.db, id), ClientSecret: secret, Rotated: true})
}

func (u *uiServer) handleDisableMachine(w http.ResponseWriter, r *http.Request, req uiRequest) {
	id, ok := u.pathID(w, r, "id")
	if !ok {
		return
	}
	if err := DisableMachine(r.Context(), u.vault, id, req.auditCtx()); err != nil {
		u.badRequest(w, r, "無効化できませんでした", err)
		return
	}
	http.Redirect(w, r, "/ui/machines", http.StatusSeeOther)
}

func (u *uiServer) handleCreateGrant(w http.ResponseWriter, r *http.Request, req uiRequest) {
	id, ok := u.pathID(w, r, "id")
	if !ok {
		return
	}
	environmentID, err := strconv.ParseInt(r.PostFormValue("environment_id"), 10, 64)
	if err != nil || environmentID <= 0 {
		u.renderError(w, r, http.StatusBadRequest, "環境の指定が不正です")
		return
	}
	if err := CreateGrant(r.Context(), u.vault.db, id, environmentID, req.auditCtx()); err != nil {
		u.badRequest(w, r, "grant を追加できませんでした", err)
		return
	}
	http.Redirect(w, r, "/ui/machines", http.StatusSeeOther)
}

func (u *uiServer) handleDeleteGrant(w http.ResponseWriter, r *http.Request, req uiRequest) {
	id, ok := u.pathID(w, r, "id")
	if !ok {
		return
	}
	envID, ok := u.pathID(w, r, "envID")
	if !ok {
		return
	}
	if err := DeleteGrant(r.Context(), u.vault.db, u.logger, id, envID, req.auditCtx()); err != nil {
		u.badRequest(w, r, "grant を削除できませんでした", err)
		return
	}
	http.Redirect(w, r, "/ui/machines", http.StatusSeeOther)
}

// ---- user ----

func (u *uiServer) handleUsers(w http.ResponseWriter, r *http.Request, req uiRequest) {
	u.renderUsers(w, r, req, nil)
}

// initialPassword は一度だけ表示する初期パスワードである。
type initialPassword struct {
	Username string
	Password string
}

func (u *uiServer) renderUsers(w http.ResponseWriter, r *http.Request, req uiRequest, created *initialPassword) {
	users, err := ListUsers(r.Context(), u.vault.db)
	if err != nil {
		u.internalError(w, r, "list users", err)
		return
	}

	data := u.page(req, "ユーザー")
	data.Users = users
	data.InitialPassword = created
	if created != nil {
		data.BFCache = "replace"
		data.BFCacheURL = "/ui/users"
	}
	u.render(w, r, "users.html", data)
}

func (u *uiServer) handleCreateUser(w http.ResponseWriter, r *http.Request, req uiRequest) {
	username := r.PostFormValue("username")

	// **初期パスワードはサーバーが生成する。** 作成者が決めた値を使うと、
	// その値が別の場所(チャット等)を経由して伝わる。
	password, err := generateInitialPassword()
	if err != nil {
		u.internalError(w, r, "generate password", err)
		return
	}

	if _, err := CreateUser(r.Context(), u.vault.db, username, password, true, req.auditCtx()); err != nil {
		u.badRequest(w, r, "ユーザーを作成できませんでした", err)
		return
	}
	u.renderUsers(w, r, req, &initialPassword{Username: username, Password: password})
}

func (u *uiServer) handleDisableUser(w http.ResponseWriter, r *http.Request, req uiRequest) {
	id, ok := u.pathID(w, r, "id")
	if !ok {
		return
	}
	// **自分自身は無効化できない。** 全 admin を締め出す事故を防ぐ。
	if id == req.User.UserID {
		u.renderError(w, r, http.StatusBadRequest, "自分自身は無効化できません")
		return
	}
	if err := DisableUser(r.Context(), u.vault.db, u.logger, id, req.auditCtx()); err != nil {
		u.badRequest(w, r, "無効化できませんでした", err)
		return
	}
	http.Redirect(w, r, "/ui/users", http.StatusSeeOther)
}

// generateInitialPassword は初期パスワードを生成する。
//
// crypto/rand 由来の 24 バイトを base64url にする(32 文字)。
func generateInitialPassword() (string, error) {
	raw, encoded, err := generateRandomToken(24)
	// 生バイト列は secret 相当。エンコード後は best effort で消す(ルール 15)。
	Zero(raw)
	return encoded, err
}

// ---- 監査ログ ----

func (u *uiServer) handleAudit(w http.ResponseWriter, r *http.Request, req uiRequest) {
	rows, err := ListAuditLogs(r.Context(), u.vault.db, uiAuditLimit)
	if err != nil {
		u.internalError(w, r, "list audit logs", err)
		return
	}
	data := u.page(req, "監査ログ")
	data.Audit = rows
	data.AuditLimit = uiAuditLimit
	u.render(w, r, "audit.html", data)
}

// ---- 補助 ----

// resolveEnv はパスの project / env を解決する。
func (u *uiServer) resolveEnv(w http.ResponseWriter, r *http.Request) (*EnvironmentRef, bool) {
	env, err := ResolveEnvironment(r.Context(), u.vault.db, r.PathValue("slug"), r.PathValue("env"))
	if errors.Is(err, ErrNotFound) {
		u.renderError(w, r, http.StatusNotFound, "見つかりません")
		return nil, false
	}
	if err != nil {
		u.internalError(w, r, "resolve environment", err)
		return nil, false
	}
	return env, true
}

// pathID はパス変数を int64 として読む。
func (u *uiServer) pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		u.renderError(w, r, http.StatusBadRequest, "指定が不正です")
		return 0, false
	}
	return id, true
}

// clientIDOf は表示用に client_id を引く。引けなくても credential の表示は
// 続ける(再発行そのものは既に成功しており、値を見せないと失われる)。
func clientIDOf(ctx context.Context, db *sql.DB, machineID int64) string {
	var clientID string
	if err := db.QueryRowContext(ctx,
		`SELECT client_id FROM machines WHERE id = ?`, machineID).Scan(&clientID); err != nil {
		return ""
	}
	return clientID
}

func envPath(env *EnvironmentRef) string {
	return "/ui/projects/" + env.ProjectSlug + "/" + env.EnvSlug
}

// redirectToEnv は environment のページへ戻す。
//
// **EnvironmentRef の slug は DB から読んだ値である**(ResolveEnvironment が
// 一致した行を返す)。リクエストの生の文字列ではないので、そのまま組み立てて
// よい。
func (u *uiServer) redirectToEnv(w http.ResponseWriter, r *http.Request, env *EnvironmentRef) {
	http.Redirect(w, r, envPath(env), http.StatusSeeOther) //nolint:gosec // G710: DB から読んだ slug である
}

func (u *uiServer) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	u.logger.ErrorContext(r.Context(), what, slog.String("error", err.Error()))
	u.renderError(w, r, http.StatusInternalServerError, "処理に失敗しました")
}

// badRequest は入力起因の失敗を返す。
//
// **エラーの中身は画面に出さない。** SQL の制約違反メッセージ等がそのまま
// 出ると、renderError の契約(「メッセージに内部情報を載せない」)が崩れる。
// 利用者に伝えるべきことは呼び出し側が msg に書き、原因は運用ログへ出す。
//
// 入力の形式に関する検証エラー(定数メッセージ)は例外的にそのまま見せる。
// 直せるのは利用者だけであり、内部の情報を含まないためである。
func (u *uiServer) badRequest(w http.ResponseWriter, r *http.Request, msg string, err error) {
	if err != nil {
		u.logger.WarnContext(r.Context(), msg, slog.String("error", err.Error()))
		if detail := userFacingReason(err); detail != "" {
			msg += ": " + detail
		}
	}
	u.renderError(w, r, http.StatusBadRequest, msg)
}

// userFacingReason は利用者に見せてよい理由を返す。
//
// **allowlist である。** 未知のエラーは空文字を返し、画面には出さない。
func userFacingReason(err error) string {
	switch {
	case errors.Is(err, ErrPasswordTooShort), errors.Is(err, ErrPasswordTooLong):
		return err.Error()
	case errors.Is(err, ErrInvalidUsername):
		return "ユーザー名の形式が正しくありません"
	case errors.Is(err, ErrNotFound):
		return "対象が見つかりません"
	case errors.Is(err, ErrSealed):
		return "サーバーが sealed です"
	case errors.Is(err, errSecretValueTooLarge), errors.Is(err, errSecretValueNotUTF8),
		errors.Is(err, errSecretValueHasNUL):
		return err.Error()
	case errors.Is(err, errMachineNameEmpty):
		return "名前を入力してください"
	case errors.Is(err, errMachineNameTooLong):
		return fmt.Sprintf("名前は %d バイト以内で入力してください", MaxMachineNameBytes)
	case errors.Is(err, errMachineNameControl):
		return "名前に使えない文字が含まれています"
	default:
		return ""
	}
}
