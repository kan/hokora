package hokora

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- credential の解決(DESIGN §11.1) ----

// mapEnv は getenv を map で差し替える(実環境に触れない)。
func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolveConfigPrecedence(t *testing.T) {
	t.Parallel()

	full := func(prefix string) map[string]string {
		return map[string]string{
			envAddr:         prefix + "-addr",
			envClientID:     prefix + "-id",
			envClientSecret: prefix + "-secret",
			envProject:      prefix + "-project",
			envEnv:          prefix + "-env",
		}
	}

	t.Run("option beats file and env", func(t *testing.T) {
		t.Parallel()

		cfg := config{
			addr: "opt-addr", clientID: "opt-id", clientSecret: "opt-secret",
			project: "opt-project", env: "opt-env",
			credentialsFile: writeCredsFile(t, full("file")),
		}
		if err := resolveConfig(&cfg, mapEnv(full("env")), os.ReadFile); err != nil {
			t.Fatalf("resolveConfig: %v", err)
		}
		if cfg.addr != "opt-addr" || cfg.clientID != "opt-id" || cfg.project != "opt-project" {
			t.Errorf("options did not win: %+v", cfg)
		}
	})

	t.Run("file beats env", func(t *testing.T) {
		t.Parallel()

		cfg := config{credentialsFile: writeCredsFile(t, full("file"))}
		if err := resolveConfig(&cfg, mapEnv(full("env")), os.ReadFile); err != nil {
			t.Fatalf("resolveConfig: %v", err)
		}
		if cfg.clientSecret != "file-secret" || cfg.env != "file-env" {
			t.Errorf("file did not win over env: %+v", cfg)
		}
	})

	t.Run("env fills the rest", func(t *testing.T) {
		t.Parallel()

		// ファイルには一部だけ書く。残りは env から埋まる。
		cfg := config{credentialsFile: writeCredsFile(t, map[string]string{envAddr: "file-addr"})}
		if err := resolveConfig(&cfg, mapEnv(full("env")), os.ReadFile); err != nil {
			t.Fatalf("resolveConfig: %v", err)
		}
		if cfg.addr != "file-addr" {
			t.Errorf("addr = %q, want file-addr", cfg.addr)
		}
		if cfg.clientID != "env-id" {
			t.Errorf("client id = %q, want env-id", cfg.clientID)
		}
	})
}

// 必須設定が欠けていれば ErrMissingConfig。**欠けている名前を挙げる**。
func TestResolveConfigMissing(t *testing.T) {
	t.Parallel()

	cfg := config{addr: "https://h:9443", clientID: "id"} // secret / project / env 欠落
	err := resolveConfig(&cfg, mapEnv(nil), os.ReadFile)
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("error = %v, want ErrMissingConfig", err)
	}
	for _, name := range []string{envClientSecret, envProject, envEnv} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the missing %q", err, name)
		}
	}
	// 揃っている名前は挙げない。
	if strings.Contains(err.Error(), envClientID) {
		t.Errorf("error names a setting that was present: %q", err)
	}
}

// $CREDENTIALS_DIRECTORY/hokora を読む(systemd LoadCredential=)。
func TestResolveConfigFromCredentialsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, credentialsFileName), map[string]string{
		envAddr: "https://h:9443", envClientID: "id", envClientSecret: "sec",
		envProject: "myapp", envEnv: "prod",
	})

	getenv := mapEnv(map[string]string{"CREDENTIALS_DIRECTORY": dir})
	var cfg config
	if err := resolveConfig(&cfg, getenv, os.ReadFile); err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.clientID != "id" || cfg.project != "myapp" {
		t.Errorf("cfg = %+v", cfg)
	}
}

// **明示指定したファイルが読めなければエラー。** systemd の fallback は
// ファイル欠如を許すが、明示指定は許さない(設定ミスを隠さない)。
func TestCredentialsFileErrors(t *testing.T) {
	t.Parallel()

	t.Run("explicit missing file is an error", func(t *testing.T) {
		t.Parallel()

		cfg := config{credentialsFile: filepath.Join(t.TempDir(), "nope")}
		err := resolveConfig(&cfg, mapEnv(nil), os.ReadFile)
		if err == nil || errors.Is(err, ErrMissingConfig) {
			t.Fatalf("error = %v, want a read error", err)
		}
	})

	t.Run("optional systemd file may be absent", func(t *testing.T) {
		t.Parallel()

		// ディレクトリはあるが hokora ファイルは無い。env で埋める。
		getenv := mapEnv(map[string]string{
			"CREDENTIALS_DIRECTORY": t.TempDir(),
			envAddr:                 "https://h:9443", envClientID: "id",
			envClientSecret: "sec", envProject: "myapp", envEnv: "prod",
		})
		var cfg config
		if err := resolveConfig(&cfg, getenv, os.ReadFile); err != nil {
			t.Fatalf("resolveConfig should fall back to env: %v", err)
		}
	})
}

func TestParseCredentials(t *testing.T) {
	t.Parallel()

	data := []byte(strings.Join([]string{
		"# comment",
		"",
		"  # indented comment",
		"HOKORA_ADDR=https://h:9443",
		"HOKORA_CLIENT_SECRET=a=b=c", // 値に = を含む
		"  HOKORA_PROJECT = myapp ",  // キー周りの空白は除去、値は verbatim
		"garbage line without equals",
	}, "\n"))

	got := parseCredentials(data)
	if got[envAddr] != "https://h:9443" {
		t.Errorf("addr = %q", got[envAddr])
	}
	// 値に = があっても最初の = で分割する。
	if got[envClientSecret] != "a=b=c" {
		t.Errorf("secret = %q, want a=b=c", got[envClientSecret])
	}
	// キーの空白は除去、値は前後空白込みで verbatim。
	if v, ok := got[envProject]; !ok || v != " myapp " {
		t.Errorf("project = %q (ok=%v), want %q", v, ok, " myapp ")
	}
	if _, ok := got["garbage line without equals"]; ok {
		t.Error("a line without '=' was stored")
	}
}

// ---- Fetch(fake server) ----

// fakeServer は Machine API の /v1/auth/token と /v1/secrets を模す。
type fakeServer struct {
	clientID     string
	clientSecret string
	token        string
	secrets      map[string]string
	sealed       bool
	authCalls    int
	// secretsCalls / secretsKeyCalls は、それぞれ一括取得(GET /v1/secrets)と
	// 単一キー取得(GET /v1/secrets/{key})が呼ばれた回数である。FetchKey が
	// 実際に単一キーのエンドポイントしか叩かないことを検査するのに使う。
	secretsCalls    int
	secretsKeyCalls int
}

func (f *fakeServer) handler(t *testing.T) http.Handler {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		f.authCalls++
		if f.sealed {
			writeJSON(t, w, http.StatusServiceUnavailable, map[string]string{"error": "sealed"})
			return
		}
		var req struct{ ClientID, ClientSecret string }
		if err := json.NewDecoder(r.Body).Decode(&struct {
			ClientID     *string `json:"client_id"`
			ClientSecret *string `json:"client_secret"`
		}{&req.ClientID, &req.ClientSecret}); err != nil {
			writeJSON(t, w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		if req.ClientID != f.clientID || req.ClientSecret != f.clientSecret {
			writeJSON(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"token": f.token, "expires_in": 900})
	})
	mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		f.secretsCalls++
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			writeJSON(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		if r.URL.Query().Get("project") == "" || r.URL.Query().Get("env") == "" {
			writeJSON(t, w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"project": r.URL.Query().Get("project"),
			"env":     r.URL.Query().Get("env"),
			"secrets": f.secrets,
		})
	})
	// 単一キー取得(FetchKey が使う)。存在しないキーは bulk と違って
	// "無い" とは言わず、grant なしと同じ forbidden に潰す(サーバーが
	// 存在情報を漏らさない)。
	mux.HandleFunc("GET /v1/secrets/{key}", func(w http.ResponseWriter, r *http.Request) {
		f.secretsKeyCalls++
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			writeJSON(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		if r.URL.Query().Get("project") == "" || r.URL.Query().Get("env") == "" {
			writeJSON(t, w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		key := r.PathValue("key")
		value, ok := f.secrets[key]
		if !ok {
			writeJSON(t, w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"project": r.URL.Query().Get("project"),
			"env":     r.URL.Query().Get("env"),
			"key":     key,
			"value":   value,
		})
	})
	return mux
}

// newFakeClient は fake サーバーと、それを信頼する Client を返す。
func newFakeClient(t *testing.T, f *fakeServer, opts ...Option) *Client {
	t.Helper()

	srv := httptest.NewTLSServer(f.handler(t))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	base := []Option{
		WithAddress(srv.URL),
		WithCredentials(f.clientID, f.clientSecret),
		WithProject("myapp"), WithEnv("prod"),
		WithRootCAs(pool),
	}
	client, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestFetch(t *testing.T) {
	t.Parallel()

	f := &fakeServer{
		clientID: "app-prod", clientSecret: "s3cr3t", token: "tok-123",
		secrets: map[string]string{"DATABASE_URL": "postgres://x", "API_TOKEN": "t0ken"},
	}
	client := newFakeClient(t, f)

	secrets, err := client.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if secrets.Len() != 2 {
		t.Fatalf("Len = %d, want 2", secrets.Len())
	}
	if v, ok := secrets.GetString("DATABASE_URL"); !ok || v != "postgres://x" {
		t.Errorf("DATABASE_URL = %q (ok=%v)", v, ok)
	}
	if got, ok := secrets.Get("API_TOKEN"); !ok || string(got) != "t0ken" {
		t.Errorf("API_TOKEN = %q (ok=%v)", got, ok)
	}
}

// **キャッシュを持たない**(DESIGN §11.2)。Fetch のたびに認証する。
func TestFetchDoesNotCache(t *testing.T) {
	t.Parallel()

	f := &fakeServer{clientID: "id", clientSecret: "sec", token: "tok", secrets: map[string]string{"K": "v"}}
	client := newFakeClient(t, f)

	for range 3 {
		if _, err := client.Fetch(t.Context()); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
	}
	if f.authCalls != 3 {
		t.Errorf("auth calls = %d, want 3 (no cached token)", f.authCalls)
	}
}

func TestFetchErrors(t *testing.T) {
	t.Parallel()

	t.Run("wrong secret", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{clientID: "id", clientSecret: "right", token: "t"}
		client := newFakeClient(t, f, WithCredentials("id", "wrong"))
		if _, err := client.Fetch(t.Context()); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("error = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("sealed", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{clientID: "id", clientSecret: "sec", token: "t", sealed: true}
		client := newFakeClient(t, f)
		if _, err := client.Fetch(t.Context()); !errors.Is(err, ErrSealed) {
			t.Fatalf("error = %v, want ErrSealed", err)
		}
	})
}

// ---- A: FetchKey(単一キー取得) ----

// FetchKey は単一キーのエンドポイントだけを叩き、bulk(GET /v1/secrets)には
// 一度も触れない。get 1 件のために grant 内の全キーを read・監査してしまう
// と、監査ログが実態(「このキーが読まれた」)と乖離する
// (cmd/hokora-client の cmdGet が bulk Fetch から FetchKey に切り替わった
// 理由と同じ。THREAT_MODEL §10.5)。
func TestFetchKey(t *testing.T) {
	t.Parallel()

	f := &fakeServer{
		clientID: "app-prod", clientSecret: "s3cr3t", token: "tok-123",
		secrets: map[string]string{"DATABASE_URL": "postgres://x", "API_TOKEN": "t0ken"},
	}
	client := newFakeClient(t, f)

	secrets, err := client.FetchKey(t.Context(), "DATABASE_URL")
	if err != nil {
		t.Fatalf("FetchKey: %v", err)
	}
	if secrets.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (only the requested key)", secrets.Len())
	}
	if v, ok := secrets.GetString("DATABASE_URL"); !ok || v != "postgres://x" {
		t.Errorf("DATABASE_URL = %q (ok=%v)", v, ok)
	}

	if f.secretsCalls != 0 {
		t.Errorf("bulk GET /v1/secrets was called %d times, want 0", f.secretsCalls)
	}
	if f.secretsKeyCalls != 1 {
		t.Errorf("GET /v1/secrets/{key} was called %d times, want 1", f.secretsKeyCalls)
	}
}

func TestFetchKeyErrors(t *testing.T) {
	t.Parallel()

	// 存在しないキーは、grant なしと同じ forbidden に潰される
	// (サーバーが存在情報を漏らさない。ルール 54 と同じ理由)。
	t.Run("unknown key maps to ErrForbidden", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{
			clientID: "id", clientSecret: "sec", token: "tok",
			secrets: map[string]string{"DATABASE_URL": "postgres://x"},
		}
		client := newFakeClient(t, f)

		if _, err := client.FetchKey(t.Context(), "NOPE"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("error = %v, want ErrForbidden", err)
		}
	})

	t.Run("wrong secret maps to ErrUnauthorized", func(t *testing.T) {
		t.Parallel()

		f := &fakeServer{clientID: "id", clientSecret: "right", token: "t"}
		client := newFakeClient(t, f, WithCredentials("id", "wrong"))

		if _, err := client.FetchKey(t.Context(), "DATABASE_URL"); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("error = %v, want ErrUnauthorized", err)
		}
	})
}

// ---- G: https:// の強制 ----

// New はサーバーアドレスに https:// しか許さない。TLS を無効化する手段は
// 提供しない(AGENTS.md ルール 31、THREAT_MODEL §5.2)。http:// の設定ミスや
// タイプミスで client_secret / トークン / secret 値が平文で流れるのを防ぐ。
func TestNewRejectsNonHTTPSAddress(t *testing.T) {
	t.Parallel()

	_, err := New(
		WithAddress("http://hokora.example.com:9443"),
		WithCredentials("id", "sec"),
		WithProject("myapp"), WithEnv("prod"),
	)
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("error = %v, want ErrMissingConfig", err)
	}
}

// https:// のアドレスは受理される(スキームの検査以外は落ちないこと)。
func TestNewAcceptsHTTPSAddress(t *testing.T) {
	t.Parallel()

	client, err := New(
		WithAddress("https://hokora.example.com:9443"),
		WithCredentials("id", "sec"),
		WithProject("myapp"), WithEnv("prod"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client == nil {
		t.Fatal("New returned a nil client")
	}
}

// **InsecureSkipVerify を提供しない。** 自己署名を信頼するには CA を積む
// 必要があり、それをしなければ TLS 検証で失敗する。
func TestTLSVerificationIsEnforced(t *testing.T) {
	t.Parallel()

	f := &fakeServer{clientID: "id", clientSecret: "sec", token: "t", secrets: map[string]string{}}
	srv := httptest.NewTLSServer(f.handler(t))
	t.Cleanup(srv.Close)

	// **CA を積まずに** Client を作る。
	client, err := New(
		WithAddress(srv.URL),
		WithCredentials("id", "sec"),
		WithProject("myapp"), WithEnv("prod"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Fetch(t.Context()); err == nil {
		t.Fatal("Fetch succeeded against an untrusted certificate")
	}

}

// ---- テスト補助 ----

func writeCredsFile(t *testing.T, kv map[string]string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), credentialsFileName)
	writeFile(t, path, kv)
	return path
}

func writeFile(t *testing.T, path string, kv map[string]string) {
	t.Helper()

	var b strings.Builder
	for k, v := range kv {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(v)
		b.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, code int, body any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
