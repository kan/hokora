package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/png"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// マニュアル(docs/manual/web-ui.md)に載せる Web UI のスクリーンショット。
//
// **撮るのは、このテストが使い捨ての DB に入れた架空のデータだけである。**
// 本物の secret、credential、マスターキー、実在のホスト名を写さないために、
// 稼働中の hokora を撮らない。画面に出る credential は、テストの終了と一緒に
// 消える DB に対してサーバーが生成した値で、どこでも使えない。
//
// 撮り直しは `make docs-screenshots`。画面(テンプレート、CSS)を変えたら
// 撮り直して、同じコミットに入れる。
const (
	screenshotDirEnv   = "HOKORA_SCREENSHOT_DIR" // 出力先。未設定なら撮影しない
	screenshotBinEnv   = "HOKORA_CHROME"         // Chromium / Chrome の実行ファイル
	screenshotFlagsEnv = "HOKORA_CHROME_FLAGS"   // ブラウザに足すフラグ(空白区切り)

	screenshotAssets = "docs/assets/screenshots"
	// screenshotSources は、撮影した時点の画面の素(templates/ と static/)の
	// ハッシュを置くファイルである。
	screenshotSources = screenshotAssets + "/sources.sha256"

	screenshotWidth     = 1000
	screenshotMaxHeight = 2400 // 撮影する窓の高さ。内容がこれに届く画面は撮れない
	screenshotMargin    = 24   // 内容の下に残す余白
)

// 架空の値。**実在の credential ではない。**
var screenshotSecrets = []struct{ key, value string }{
	{"DATABASE_URL", "postgres://app:" + "example-password@db.example.internal:5432/app"},
	{"SESSION_SECRET", "example-session-secret-0123456789"},
	{"SMTP_PASSWORD", "example-smtp-password"},
}

// docScreenshot は 1 枚分の画面である。
type docScreenshot struct {
	name string // 出力は <name>.png
	body string // 画面の HTML
	// height は、画面の上から何 px までを撮るかである。0 なら内容の下端まで。
	// 見せたい部分が画面の上にだけあるときに使う。
	height int
}

// TestDocsScreenshots は、マニュアルに載せる画面を描く。
//
// 画面を描いて中身を確かめるところまでは、いつも走る(撮影用のデータの投入が、
// 本体の変更で壊れたことに気付くため)。**画像を撮るのは、出力先を環境変数で
// 渡されたときだけである。**
func TestDocsScreenshots(t *testing.T) {
	t.Parallel()

	shots := renderDocScreenshots(t)
	if dir := os.Getenv(screenshotDirEnv); dir != "" {
		captureDocScreenshots(t, shots, dir)
	}

	// 撮る画面、置いてある画像、文書からの参照の 3 つが、同じ集合であること。
	// 画面を足したのに参照していない、参照しているのに画像が無い、使わなく
	// なった画像が残っている、のどれも落とす。
	want := make([]string, 0, len(shots))
	for _, shot := range shots {
		want = append(want, shot.name)
	}
	slices.Sort(want)
	if got := screenshotFiles(t); !slices.Equal(got, want) {
		t.Errorf("images in %s = %v, want %v (run `make docs-screenshots`, remove leftovers)", screenshotAssets, got, want)
	}
	if got := screenshotReferences(t); !slices.Equal(got, want) {
		t.Errorf("screenshots referenced from the docs = %v, want %v", got, want)
	}

	// **画面の素が、撮影した時点から変わっていないこと。** 画像そのものは
	// 比べられない(credential の値と、撮った環境のフォントで変わる)ので、
	// 素のほうを比べる。見た目に影響しない変更でも落ちる。
	recorded, err := os.ReadFile(screenshotSources)
	if err != nil {
		t.Fatalf("read %s (run `make docs-screenshots`): %v", screenshotSources, err)
	}
	if got := screenshotSourcesHash(t); strings.TrimSpace(string(recorded)) != got {
		t.Errorf("templates/ or static/ changed since the screenshots were taken: "+
			"run `make docs-screenshots` and commit the images with %s", screenshotSources)
	}
}

// screenshotFiles は、置いてある画像の名前(拡張子を除く)を整列して返す。
func screenshotFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(screenshotAssets, "*.png"))
	if err != nil {
		t.Fatalf("list %s: %v", screenshotAssets, err)
	}
	names := make([]string, 0, len(paths))
	for _, p := range paths {
		names = append(names, strings.TrimSuffix(filepath.Base(p), ".png"))
	}
	slices.Sort(names)
	return names
}

var screenshotRefRE = regexp.MustCompile(`assets/screenshots/([A-Za-z0-9_-]+)\.png`)

// screenshotReferences は、docs/ の Markdown が参照している画像の名前を
// 整列して返す。
func screenshotReferences(t *testing.T) []string {
	t.Helper()

	seen := map[string]struct{}{}
	err := filepath.WalkDir("docs", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".md" {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: リポジトリの docs/ の下である
		if err != nil {
			return err
		}
		for _, m := range screenshotRefRE.FindAllSubmatch(data, -1) {
			seen[string(m[1])] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}
	return slices.Sorted(maps.Keys(seen))
}

// screenshotSourcesHash は、画面の素(バイナリに埋め込む templates/ と static/)の
// ハッシュを返す。
func screenshotSourcesHash(t *testing.T) string {
	t.Helper()

	h := sha256.New()
	for _, fsys := range []fs.FS{templatesFS, staticFS} {
		// WalkDir は名前の順に辿るので、結果は環境によらない。
		err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%s %d\n", path, len(data))
			h.Write(data)
			return nil
		})
		if err != nil {
			t.Fatalf("walk the embedded files: %v", err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// renderDocScreenshots は、架空のデータを入れた Web UI から各画面の HTML を取る。
func renderDocScreenshots(t *testing.T) []docScreenshot {
	t.Helper()

	f, api := newScreenshotFixture(t)
	var shots []docScreenshot
	add := func(name string, height int, w *httptest.ResponseRecorder, marker string) {
		t.Helper()
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, marker) {
			t.Fatalf("screenshot %q: status %d, marker %q not found", name, w.Code, marker)
		}
		shots = append(shots, docScreenshot{name: name, body: body, height: height})
	}
	mustRedirect := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s = %d (body %q)", what, w.Code, w.Body.String())
		}
	}

	add("login", 0, f.do(t, http.MethodGet, "/ui/login", nil, false), `action="/ui/login"`)
	add("unseal", 0, f.get(t, "/ui/unseal"), `action="/ui/unseal"`)
	// unseal も画面から行う(監査ログに、他の行と同じ時計の時刻で残すため)。
	// このマスターキーは、テストの終了と一緒に消える DB のものである。
	mustRedirect("unseal", f.post(t, "/ui/unseal", url.Values{"master_key": {EncodeMasterKey(f.mk)}}))

	mustRedirect("create project", f.post(t, "/ui/projects",
		url.Values{"slug": {"myapp"}, "name": {"顧客向け Web アプリ"}}))
	mustRedirect("create project", f.post(t, "/ui/projects",
		url.Values{"slug": {"billing"}, "name": {"請求バッチ"}}))
	for _, env := range [][2]string{{"prod", "本番"}, {"staging", "検証"}} {
		mustRedirect("create environment", f.post(t, "/ui/projects/myapp/environments",
			url.Values{"slug": {env[0]}, "name": {env[1]}}))
	}
	for _, s := range screenshotSecrets {
		mustRedirect("put item", f.post(t, "/ui/projects/myapp/prod/items",
			url.Values{"key": {s.key}, "value": {s.value}}))
	}
	// 版が 2 の item を 1 つ作る(一覧の「版」の列に違いを出す)。
	mustRedirect("put item", f.post(t, "/ui/projects/myapp/prod/items",
		url.Values{"key": {screenshotSecrets[0].key}, "value": {screenshotSecrets[0].value}}))

	add("projects", 0, f.get(t, "/ui/"), "billing")
	add("environment", 0, f.get(t, "/ui/projects/myapp/prod"), "SMTP_PASSWORD")
	add("reveal", 0, f.post(t, "/ui/projects/myapp/prod/items/DATABASE_URL/reveal", nil), "db.example.internal")

	// credential の枠までを撮る。その下は environment の画面と同じである。
	created := f.post(t, "/ui/projects/myapp/prod/machines", url.Values{"name": {"web-01"}})
	add("credential", 550, created, "HOKORA_CLIENT_SECRET")
	if w := f.post(t, "/ui/machines", url.Values{"name": {"batch-01"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}
	staging, err := ResolveEnvironment(t.Context(), f.store.DB(), "myapp", "staging")
	if err != nil {
		t.Fatalf("ResolveEnvironment: %v", err)
	}
	var batchID int64
	if err := f.store.DB().QueryRowContext(t.Context(),
		`SELECT id FROM machines WHERE name = ?`, "batch-01").Scan(&batchID); err != nil {
		t.Fatalf("look up the machine: %v", err)
	}
	mustRedirect("create grant", f.post(t, "/ui/machines/"+itoa(batchID)+"/grants",
		url.Values{"environment_id": {itoa(staging.EnvironmentID)}}))

	// マシンからの取得を 2 回入れる(監査ログに secret.read の行を出す)。
	api.clientID, api.secret = credentialFromPage(t, created.Body.String())
	token := api.token(t)
	for _, path := range []string{"/v1/secrets?project=myapp&env=prod", "/v1/secrets/DATABASE_URL?project=myapp&env=prod"} {
		if w := api.do(t, http.MethodGet, path, token, nil); w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (body %q)", path, w.Code, w.Body.String())
		}
	}

	add("machines", 0, f.get(t, "/ui/machines"), "batch-01")
	add("audit", 0, f.get(t, "/ui/audit"), "secret.read")
	return shots
}

// newScreenshotFixture は、同じ vault に載った、時刻が少しずつ進む Web UI と
// Machine API を返す。
//
// fixture の時計は 1 点に止まっているので、そのままでは監査ログの時刻が
// 全て同じになる。
func newScreenshotFixture(t *testing.T) (*uiFixture, *apiFixture) {
	t.Helper()

	f := newUIFixture(t)
	api := &apiFixture{api: newMachineAPI(f.vault, discardLogger()), vault: f.vault, store: f.store}

	// リクエストは 1 つずつ直列に送るので、ロックは要らない。
	now := time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		now = now.Add(41 * time.Second)
		return now
	}
	f.ui.now = clock
	api.api.now = clock

	// newUIFixture のセッションは vaultNow で作られていて、この時計では
	// 期限切れになる。作り直す。
	f.rawSess = newTestSessionAt(t, f.store, f.userID, now)
	f.csrf = csrfToken(f.rawSess)
	return f, api
}

var credentialCodeRE = regexp.MustCompile(`<dt>(HOKORA_CLIENT_(?:ID|SECRET))</dt><dd><code[^>]*>([^<]+)</code>`)

// credentialFromPage は、作成直後の画面から credential を読み取る。
func credentialFromPage(t *testing.T, body string) (clientID, clientSecret string) {
	t.Helper()

	for _, m := range credentialCodeRE.FindAllStringSubmatch(body, -1) {
		switch m[1] {
		case "HOKORA_CLIENT_ID":
			clientID = m[2]
		case "HOKORA_CLIENT_SECRET":
			clientSecret = m[2]
		}
	}
	if clientID == "" || clientSecret == "" {
		t.Fatal("the credential was not found on the page")
	}
	return clientID, clientSecret
}

// captureDocScreenshots は、描いておいた HTML を headless の Chromium で撮る。
//
// ブラウザにログインさせない。描いておいた HTML をそのまま返すサーバーを立て、
// CSS などの静的ファイルだけを本物の mux から返す。
func captureDocScreenshots(t *testing.T, shots []docScreenshot, dir string) {
	t.Helper()

	chrome := os.Getenv(screenshotBinEnv)
	if chrome == "" {
		t.Fatalf("set %s to a Chromium / Chrome binary", screenshotBinEnv)
	}
	//nolint:gosec // G703: 出力先は、撮影する人が環境変数で指定したディレクトリである
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	ui, err := newUIServer(newSealedVault(t), discardLogger(), newRateLimiter(unsealRate, 1))
	if err != nil {
		t.Fatalf("newUIServer: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /ui/static/", ui.uiMux())
	for _, shot := range shots {
		mux.HandleFunc("GET /shot/"+shot.name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if _, err := w.Write([]byte(shot.body)); err != nil {
				t.Logf("write %s: %v", r.URL.Path, err)
			}
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, shot := range shots {
		out := filepath.Join(dir, shot.name+".png")
		raw := filepath.Join(t.TempDir(), shot.name+".png")

		// 追加のフラグ(sandbox を使えない環境での --no-sandbox など)は、
		// 撮影する人が明示して渡す。既定では付けない。
		args := append(strings.Fields(os.Getenv(screenshotFlagsEnv)),
			"--headless=new",
			"--hide-scrollbars",
			"--force-device-scale-factor=1",
			"--window-size="+itoa(screenshotWidth)+","+itoa(screenshotMaxHeight),
			"--user-data-dir="+t.TempDir(),
			"--screenshot="+raw,
			srv.URL+"/shot/"+shot.name,
		)
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		//nolint:gosec // G204: 実行ファイルとフラグは、撮影する人が環境変数で指定したものである
		cmd := exec.CommandContext(ctx, chrome, args...)
		// 止めた後に子プロセスが出力のパイプを持ったまま残っても、待ち続けない。
		cmd.WaitDelay = 5 * time.Second
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s: %v\n%s", chrome, err, output)
		}
		if err := cropScreenshot(raw, out, shot.height); err != nil {
			t.Fatalf("crop %s: %v", shot.name, err)
		}
		t.Logf("wrote %s", out)
	}

	//nolint:gosec // G703: 出力先は、撮影する人が環境変数で指定したディレクトリの下である
	if err := os.WriteFile(filepath.Join(dir, filepath.Base(screenshotSources)),
		[]byte(screenshotSourcesHash(t)+"\n"), 0o600); err != nil {
		t.Fatalf("record the hash of the sources: %v", err)
	}
}

// cropScreenshot は、画面の下の余白(背景色だけの行)を切り落として書き出す。
//
// headless の Chromium は窓の大きさでしか撮れないので、縦に長い窓で撮ってから
// 内容のある所までに詰める。**内容が窓の下端に届いていたら、エラーにする。**
//
// 背景色は左下の画素で決めている。下端に、一様な色の行が余白の分より長く
// 続く画面(下端まで届く単色の帯など)は、内容でも背景として切り落とす。
// 撮り直した画像は目で確かめる。
func cropScreenshot(src, dst string, height int) error {
	data, err := os.ReadFile(src) //nolint:gosec // G304: このテストが作った一時ファイルである
	if err != nil {
		return err
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}

	bounds := img.Bounds()
	background := img.At(bounds.Min.X, bounds.Max.Y-1)
	bottom := bounds.Min.Y
scan:
	for y := bounds.Max.Y - 1; y >= bounds.Min.Y; y-- {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if img.At(x, y) != background {
				bottom = y + 1
				break scan
			}
		}
	}
	if bottom+screenshotMargin > bounds.Max.Y {
		return fmt.Errorf("the page does not fit in %d px: raise screenshotMaxHeight", bounds.Dy())
	}
	bottom += screenshotMargin
	if height > 0 {
		bottom = min(bottom, bounds.Min.Y+height)
	}

	cropped, ok := img.(interface {
		SubImage(r image.Rectangle) image.Image
	})
	if !ok {
		return fmt.Errorf("unexpected image type %T", img)
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, cropped.SubImage(image.Rect(bounds.Min.X, bounds.Min.Y, bounds.Max.X, bottom))); err != nil {
		return err
	}
	//nolint:gosec // G703: 出力先は、撮影する人が環境変数で指定したディレクトリの下である
	return os.WriteFile(dst, buf.Bytes(), 0o600)
}
