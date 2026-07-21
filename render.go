package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"time"
)

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// contentSecurityPolicy は Web UI の CSP である(DESIGN §8.3)。
//
// **CDN から何も読み込まない**(AGENTS.md ルール 42)。`'unsafe-inline'` を
// 入れないので、インラインの script / style も動かない。bfcache 対策の
// JavaScript を別ファイルにしているのはこのためである(§9.3)。
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// securityHeaders は Web UI の全レスポンスに付けるヘッダである(DESIGN §8.3)。
//
// **Cache-Control だけでは bfcache を防げない**(§9.3)。static/bfcache.js が
// pageshow の persisted を見て退避する。ここはその前提の一層目である。
func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	h.Set("Pragma", "no-cache")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=31536000")
}

// withUIHeaders は uiMux に被せるミドルウェアである。
//
// **レスポンス圧縮は有効にしない**(AGENTS.md ルール 43)。CSRF トークンが
// 全ページに埋まる設計なので、圧縮と反射文字列が同居すると理論上 BREACH の
// 対象になる。net/http は既定で圧縮しないが、ここに gzip を足さないこと。
func withUIHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		next.ServeHTTP(w, r)
	})
}

// pageData はテンプレートに渡す唯一の型である。
//
// **`template.HTML` / `template.JS` / `template.URL` を使わない**
// (AGENTS.md ルール 40)。全て文字列として渡し、html/template の自動
// エスケープに委ねる。
type pageData struct {
	Title string
	Error string
	User  *SessionUser
	// CSRFToken はフォームに埋める値である(セッションから導出。DB に無い)。
	CSRFToken string

	// BFCache は body の data-bfcache 属性である(DESIGN §9.3)。
	//
	//	"reload"  通常のページ
	//	"replace" **平文を含むページ。** DOM を消してから安全な GET へ退避する
	BFCache    string
	BFCacheURL string

	Sealed bool

	Projects     []ProjectRow
	Project      *Project
	Environments []EnvironmentRow
	Env          *EnvironmentRef
	Items        []ItemRow
	Versions     []VersionRow

	Key     string
	Value   string
	Version int64

	Machines   []MachineRow
	Grantable  []GrantableEnvironment
	Credential *machineCredential

	Users           []UserRow
	InitialPassword *initialPassword

	Audit      []AuditRow
	AuditLimit int
}

// parseTemplates は embed したテンプレートを起動時に一度だけパースする
// (DESIGN §9.6)。
//
// **ページごとに独立した Template を作る。** html/template の名前空間は
// 1 つの Template 内で共有されるため、全ページを 1 度にパースすると、
// 各ページが定義する "content" が互いを上書きし、**最後にパースされた
// ページが全ページで描画される。** ページ単位に分けることでしか防げない。
func parseTemplates() (map[string]*template.Template, error) {
	pages, err := fs.Glob(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}

	out := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		name := path.Base(page)
		if name == baseTemplate {
			continue
		}
		tmpl, err := template.New(baseTemplate).Funcs(templateFuncs()).
			ParseFS(templatesFS, "templates/"+baseTemplate, page)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		out[name] = tmpl
	}
	if len(out) == 0 {
		return nil, errors.New("no templates were embedded")
	}
	return out, nil
}

// baseTemplate は共通のレイアウトである。
const baseTemplate = "base.html"

// templateFuncs はテンプレートから呼べる関数である。
//
// **HTML を組み立てる関数を置かない。** ここに置いてよいのは、文字列や
// 数値を整形するものだけである(出力は必ずエスケープされる)。
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatTime": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
	}
}

// page はテンプレートに渡す共通部分を組み立てる。
func (u *uiServer) page(req uiRequest, title string) pageData {
	return pageData{
		Title:     title,
		User:      req.User,
		CSRFToken: req.User.CSRFToken,
		BFCache:   "reload",
		Sealed:    u.vault.Status().State != StateUnsealed,
	}
}

func (u *uiServer) pageWithError(req uiRequest, title, msg string) pageData {
	data := u.page(req, title)
	data.Error = msg
	return data
}

// render は 200 でテンプレートを描画する。
func (u *uiServer) render(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	u.renderStatus(w, r, http.StatusOK, name, data)
}

// renderStatus はステータスを指定してテンプレートを描画する。
//
// **バッファに書き切ってから送る。** テンプレートの実行が途中で失敗すると、
// 半端な HTML(場合によっては平文の一部)を送った後でエラーになる。
func (u *uiServer) renderStatus(w http.ResponseWriter, r *http.Request, code int, name string, data pageData) {
	if data.BFCache == "" {
		data.BFCache = "reload"
	}

	tmpl, ok := u.tmpl[name]
	if !ok {
		u.logger.ErrorContext(r.Context(), "unknown template", slog.String("template", name))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		u.logger.ErrorContext(r.Context(), "render template",
			slog.String("template", name), slog.String("error", err.Error()))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if _, err := w.Write(buf.Bytes()); err != nil {
		u.logger.WarnContext(r.Context(), "could not write the response",
			slog.String("error", err.Error()))
	}
}

// renderError はエラーページを描画する。
//
// **メッセージに内部情報を載せない。** 呼び出し側が渡す文言は利用者向けの
// 説明に限り、原因の詳細は運用ログへ出す(internalError を使う)。
func (u *uiServer) renderError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	data := pageData{Title: "エラー", Error: msg, BFCache: "reload"}

	// セッションがある場合はヘッダを出せるよう、ユーザーを載せる。
	if raw, err := sessionTokenFromRequest(r); err == nil {
		defer Zero(raw)
		if su, err := LookupSession(r.Context(), u.vault.db, raw, u.now()); err == nil {
			data.User = su
			data.CSRFToken = su.CSRFToken
		}
	}
	u.renderStatus(w, r, code, "error.html", data)
}
