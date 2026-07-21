package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fullPageData は全テンプレートを描画できるだけの値を持つ pageData を返す。
//
// テンプレートは nil のフィールドを辿ると実行時に失敗する。**起動時に
// パースが通ることと、実際に描画できることは別である**(パースは
// フィールドの有無を検査しない)。
func fullPageData() pageData {
	at := vaultNow.UTC()
	lastAuth := at
	// 「一度だけ表示される値」のダミー。**実在の credential ではない。**
	// 変数に置いているのは、リテラルの直書きを秘密の埋め込みと見なす
	// 静的解析(gosec G101)を避けるためである。
	shownOnce := "shown-once-" + "dummy-value"
	csrf := "csrf-" + "dummy-value"
	return pageData{
		Title:     "テスト",
		User:      &SessionUser{UserID: 1, Username: "admin", MustChangePW: true},
		CSRFToken: csrf,
		BFCache:   "reload",
		Projects:  []ProjectRow{{ID: 1, Slug: "myapp", Name: "My App", Envs: 1, Items: 2}},
		Project:   &Project{ID: 1, Slug: "myapp", Name: "My App"},
		Environments: []EnvironmentRow{
			{ID: 2, Slug: "prod", Name: "prod", Items: 2},
		},
		Env:   &EnvironmentRef{ProjectSlug: "myapp", EnvSlug: "prod", ProjectID: 1, EnvironmentID: 2},
		Items: []ItemRow{{ID: 3, Key: "DATABASE_URL", Version: 2, UpdatedAt: at, CreatedBy: "user:1"}},
		Versions: []VersionRow{
			{Version: 2, CreatedAt: at, CreatedBy: "user:1", Current: true},
			{Version: 1, CreatedAt: at, CreatedBy: "user:1"},
		},
		Key:     "DATABASE_URL",
		Value:   "plain-text-value",
		Version: 1,
		Machines: []MachineRow{{
			ID: 1, ClientID: "app-prod", Name: "app", LastAuthAt: &lastAuth,
			Grants: []GrantRow{{EnvironmentID: 2, ProjectSlug: "myapp", EnvSlug: "prod"}},
		}},
		Credential:      &machineCredential{ClientID: "app-prod", ClientSecret: shownOnce},
		Users:           []UserRow{{ID: 1, Username: "admin", CreatedAt: at}},
		InitialPassword: &initialPassword{Username: "operator", Password: shownOnce},
		Audit: []AuditRow{{
			At: at, Actor: "user:1", Action: string(ActionSecretReveal),
			Target: "myapp/prod/DATABASE_URL", Result: string(ResultSuccess), RemoteAddr: "10.8.0.9",
		}},
		AuditLimit: uiAuditLimit,
	}
}

// pageMarkers は各ページに固有の文字列である。
//
// **他のページには現れない文字列を選ぶこと。** このテストの目的は
// 「ページ X を要求したら X が描かれる」ことの確認であり、共通のヘッダや
// 他ページにも出る文言では、取り違えを検出できない。
var pageMarkers = map[string]string{
	"audit.html":       "直近",
	"dashboard.html":   "プロジェクトを作成",
	"environment.html": "item を作成 / 更新",
	"error.html":       "ダッシュボードへ戻る",
	"history.html":     " の履歴",
	"login.html":       `action="/ui/login"`,
	"machines.html":    "アプリを作成",
	"password.html":    `name="confirm_password"`,
	"project.html":     "環境を作成",
	"reveal.html":      `<pre class="plaintext">`,
	"unseal.html":      "unseal する",
	"users.html":       "ユーザーを作成",
}

// **全ページが描画でき、互いの content を上書きしない。**
//
// html/template の名前空間は 1 つの Template 内で共有される。全ページを
// まとめてパースすると、各ページが定義する "content" が互いを上書きし、
// **最後にパースされたページが全ページで描画される。** ページ単位に
// Template を分けていることでしか防げないので、その分離自体を検査する。
func TestParseTemplatesRendersEachPageIndependently(t *testing.T) {
	t.Parallel()

	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	// base.html はレイアウトなので、ページとしては登録されない。
	if _, ok := tmpl[baseTemplate]; ok {
		t.Errorf("%s is registered as a page", baseTemplate)
	}
	if len(tmpl) != len(pageMarkers) {
		t.Errorf("%d templates were parsed, want %d (update pageMarkers)", len(tmpl), len(pageMarkers))
	}

	u := &uiServer{tmpl: tmpl, logger: discardLogger()}
	for name, marker := range pageMarkers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, ok := tmpl[name]; !ok {
				t.Fatalf("%s was not parsed", name)
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ui/", nil)
			u.renderStatus(w, r, http.StatusOK, name, fullPageData())

			if w.Code != http.StatusOK {
				t.Fatalf("render %s = %d (body %q)", name, w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, marker) {
				t.Errorf("%s does not contain its own marker %q", name, marker)
			}
			// **他のページの content が紛れ込んでいないこと。**
			for other, otherMarker := range pageMarkers {
				if other == name {
					continue
				}
				if strings.Contains(body, otherMarker) {
					t.Errorf("%s contains the marker of %s (%q)", name, other, otherMarker)
				}
			}
			// 共通レイアウトが被さっていること。
			if !strings.Contains(body, "<!doctype html>") || !strings.Contains(body, "/ui/static/bfcache.js") {
				t.Errorf("%s was not wrapped by %s", name, baseTemplate)
			}
		})
	}
}

// **テンプレートの自動エスケープに委ねる**(AGENTS.md ルール 40)。
//
// secret の平文は攻撃者が値を決められる場所である(machine が書ける)。
// `template.HTML` 等でエスケープを外すと、**平文の中身がそのまま
// スクリプトとして動く。**
func TestTemplatesEscapeUntrustedValues(t *testing.T) {
	t.Parallel()

	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	u := &uiServer{tmpl: tmpl, logger: discardLogger()}

	const payload = `</pre><script>alert(1)</script>`
	data := fullPageData()
	data.Value = payload
	data.Key = payload
	data.Title = payload

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ui/", nil)
	u.renderStatus(w, r, http.StatusOK, "reveal.html", data)

	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("the payload was rendered verbatim: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the payload was not escaped: %q", body)
	}
}

// **知らないテンプレート名は 500 で止める。**
//
// 名前を間違えた場合に空の 200 を返すと、ハンドラは成功したつもりのまま
// 進む。描画は必ずバッファに書き切ってから送るので、途中まで送った状態にも
// ならない。
func TestRenderStatusRejectsAnUnknownTemplate(t *testing.T) {
	t.Parallel()

	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	u := &uiServer{tmpl: tmpl, logger: discardLogger()}

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ui/", nil)
	u.renderStatus(w, r, http.StatusOK, "nosuchpage.html", fullPageData())

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "<!doctype html>") {
		t.Error("a page was rendered for an unknown template name")
	}
}

// **BFCache を指定し忘れたら "reload" になる。**
//
// 空文字のまま描画すると `data-bfcache=""` になり、bfcache.js は既定の
// reload を選ぶ。属性としては同じ結果だが、**「指定漏れが replace に
// 化けない」ことを描画側で固定しておく**(平文ページは必ず明示的に
// replace を指定する)。
func TestRenderStatusDefaultsToReloadBFCache(t *testing.T) {
	t.Parallel()

	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	u := &uiServer{tmpl: tmpl, logger: discardLogger()}

	data := fullPageData()
	data.BFCache = ""

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ui/", nil)
	u.renderStatus(w, r, http.StatusOK, "dashboard.html", data)

	assertBFCacheReload(t, w.Body.String())
}

// **セキュリティヘッダは静的アセットにも付く。**
//
// withUIHeaders は mux 全体に被せるので、テンプレートを描かない経路
// (static、リダイレクト、エラー)でも落ちない。
func TestWithUIHeadersAppliesToEveryResponse(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ui/static/style.css", nil)
	withUIHeaders(next).ServeHTTP(w, r)

	if got := w.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Errorf("CSP = %q, want %q", got, contentSecurityPolicy)
	}
	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// formatTime はローカル時刻で描画する(監査ログの時刻が読めること)。
func TestTemplateFuncFormatTime(t *testing.T) {
	t.Parallel()

	fn, ok := templateFuncs()["formatTime"].(func(time.Time) string)
	if !ok {
		t.Fatal("formatTime is missing or has an unexpected signature")
	}
	at := time.Unix(1700000000, 0)
	if got, want := fn(at), at.Local().Format("2006-01-02 15:04:05"); got != want {
		t.Errorf("formatTime = %q, want %q", got, want)
	}
}
