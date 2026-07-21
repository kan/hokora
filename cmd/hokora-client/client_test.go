package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/kan/hokora/sdk"
)

// クライアントは root のサーバー実装(machineAPI)を import できない
// (別パッケージ・別バイナリ)。そこで SDK のテストと同じく **fake サーバー**
// を立てて往復検証する。実サーバーとの往復は root / api レイヤーのテストが
// 担う。ここでの関心は「フラグ・環境・終了コード・CA 読み込みの配線」である。

const (
	testClientID = "app-prod"
	testSecretID = "s3cr3t" // client_secret
	testToken    = "tok-123"
	testProject  = "myapp"
	testEnv      = "prod"
	testDBURL    = "postgres://db.internal:5432/app"
	testAPIToken = "t0ken"
)

// fakeServer は Machine API の /v1/auth/token と /v1/secrets を模す。
// grant は project/env の完全一致でモデル化する(不一致なら 403)。
type fakeServer struct {
	secrets map[string]string
}

func (f *fakeServer) handler(t *testing.T) http.Handler {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(t, w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		if req.ClientID != testClientID || req.ClientSecret != testSecretID {
			writeJSON(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"token": testToken, "expires_in": 900})
	})
	mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			writeJSON(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		// grant は project/env の一致で表現する。上書きフラグが実際に
		// サーバーへ届いているかを、不一致→403 で観測できる。
		if r.URL.Query().Get("project") != testProject || r.URL.Query().Get("env") != testEnv {
			writeJSON(t, w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"project": testProject, "env": testEnv, "secrets": f.secrets,
		})
	})
	// 単一キー取得(cmdGet はこちらを使う)。存在しないキー・grant 不一致は
	// どちらも 403 に潰す(サーバーが存在情報を漏らさない)。
	mux.HandleFunc("GET /v1/secrets/{key}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			writeJSON(t, w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		if r.URL.Query().Get("project") != testProject || r.URL.Query().Get("env") != testEnv {
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
			"project": testProject, "env": testEnv, "key": key, "value": value,
		})
	})
	return mux
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

// clientTestServer は fake サーバーと、それを信頼する credential/CA を用意する。
type clientTestServer struct {
	url      string
	credFile string
	caFile   string
}

func newClientTestServer(t *testing.T) *clientTestServer {
	t.Helper()

	f := &fakeServer{secrets: map[string]string{
		"DATABASE_URL": testDBURL,
		"API_TOKEN":    testAPIToken,
	}}
	srv := httptest.NewTLSServer(f.handler(t))
	t.Cleanup(srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeCertPEM(t, caFile, srv.Certificate())

	credFile := filepath.Join(t.TempDir(), "credentials")
	writeCredentials(t, credFile, map[string]string{
		"HOKORA_ADDR":          srv.URL,
		"HOKORA_CLIENT_ID":     testClientID,
		"HOKORA_CLIENT_SECRET": testSecretID,
		"HOKORA_PROJECT":       testProject,
		"HOKORA_ENV":           testEnv,
	})

	return &clientTestServer{url: srv.URL, credFile: credFile, caFile: caFile}
}

// args は共通フラグ(--credentials / --ca)に続けて残りの引数を並べる。
func (s *clientTestServer) args(rest ...string) []string {
	return append([]string{"--credentials", s.credFile, "--ca", s.caFile}, rest...)
}

func TestCmdGet(t *testing.T) {
	s := newClientTestServer(t)

	var err error
	stdout := captureStdout(t, func() {
		err = cmdGet(context.Background(), s.args("DATABASE_URL"))
	})
	if err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	// 値そのもの + 改行 1 個の完全一致(余分な改行が付かないこと)。
	if want := testDBURL + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// 存在しないキーは、単一キー取得だと **grant なしと同じ forbidden** になる
// (サーバーが存在情報を漏らさない。bulk 取得のように「無い」とは言わない)。
func TestCmdGetUnknownKey(t *testing.T) {
	s := newClientTestServer(t)

	err := cmdGet(context.Background(), s.args("NOPE"))
	if !errors.Is(err, sdk.ErrForbidden) {
		t.Fatalf("error = %v, want sdk.ErrForbidden", err)
	}
}

// --ca を渡さなければ自己署名証明書は信頼されず失敗する
// (**InsecureSkipVerify 相当が無いこと**の裏取り)。
func TestCmdGetRejectsUntrustedTLS(t *testing.T) {
	s := newClientTestServer(t)

	err := cmdGet(context.Background(), []string{"--credentials", s.credFile, "DATABASE_URL"})
	if err == nil {
		t.Fatal("cmdGet trusted an unknown CA")
	}
}

// --ca フラグ省略時に $HOKORA_CA_FILE がデフォルト値として使われること。
func TestCADefaultFromEnv(t *testing.T) {
	s := newClientTestServer(t)
	t.Setenv(envCAFile, s.caFile)

	var err error
	stdout := captureStdout(t, func() {
		err = cmdGet(context.Background(), []string{"--credentials", s.credFile, "DATABASE_URL"})
	})
	if err != nil {
		t.Fatalf("cmdGet with $%s set but no --ca flag: %v", envCAFile, err)
	}
	if want := testDBURL + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// --addr が credentials ファイルの HOKORA_ADDR を上書きすること。ファイルに
// 到達不能アドレスを書き、--addr 指定で本物へ到達することで裏取りする。
func TestOverrideAddr(t *testing.T) {
	s := newClientTestServer(t)

	// 誰も listen していないポート(bind してすぐ閉じる)。
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	unreachable := "https://" + ln.Addr().String()
	if closeErr := ln.Close(); closeErr != nil {
		t.Fatalf("close listener: %v", closeErr)
	}

	credFile := filepath.Join(t.TempDir(), "credentials")
	writeCredentials(t, credFile, map[string]string{
		"HOKORA_ADDR":          unreachable,
		"HOKORA_CLIENT_ID":     testClientID,
		"HOKORA_CLIENT_SECRET": testSecretID,
		"HOKORA_PROJECT":       testProject,
		"HOKORA_ENV":           testEnv,
	})

	// 対照: 誤ったアドレスがそのまま使われ失敗すること。
	if err := cmdGet(context.Background(), []string{"--credentials", credFile, "--ca", s.caFile, "DATABASE_URL"}); err == nil {
		t.Fatal("cmdGet succeeded despite an unreachable HOKORA_ADDR")
	}

	// --addr が上書きし、本物のサーバーへ到達すること。
	var getErr error
	stdout := captureStdout(t, func() {
		getErr = cmdGet(context.Background(), []string{
			"--credentials", credFile, "--ca", s.caFile, "--addr", s.url, "DATABASE_URL",
		})
	})
	if getErr != nil {
		t.Fatalf("cmdGet with --addr override: %v", getErr)
	}
	if want := testDBURL + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// --project / --env の上書き。ファイルは正しい myapp/prod のまま、フラグで
// 存在しない値を指定すると 403 になる(= フラグが実際にサーバーへ届いている)。
func TestOverrideProjectAndEnv(t *testing.T) {
	s := newClientTestServer(t)

	tests := []struct{ name, flag, val string }{
		{"project", "--project", "no-such-project"},
		{"env", "--env", "no-such-env"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdGet(context.Background(), s.args(tt.flag, tt.val, "DATABASE_URL"))
			if !errors.Is(err, sdk.ErrForbidden) {
				t.Fatalf("cmdGet with %s %s = %v, want sdk.ErrForbidden", tt.flag, tt.val, err)
			}
		})
	}
}

func TestLoadCAPoolMissingFile(t *testing.T) {
	if _, err := loadCAPool(filepath.Join(t.TempDir(), "does-not-exist.pem")); err == nil {
		t.Fatal("loadCAPool with a nonexistent file succeeded")
	}
}

func TestLoadCAPoolNoCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(path, []byte("this is not a PEM certificate\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := loadCAPool(path)
	if err == nil {
		t.Fatal("loadCAPool with no PEM certificates succeeded")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name the file", err)
	}
}

func TestCmdRun(t *testing.T) {
	s := newClientTestServer(t)

	var err error
	stdout := captureStdout(t, func() {
		err = cmdRun(context.Background(), s.args("--", "sh", "-c", `printf '%s' "$DATABASE_URL"`))
	})
	if err != nil {
		t.Fatalf("cmdRun: %v", err)
	}
	if stdout != testDBURL {
		t.Errorf("child saw DATABASE_URL = %q, want %q", stdout, testDBURL)
	}
}

// run は注入した secret に加えて **親の環境も** 子に引き継ぐ。
func TestCmdRunInheritsParentEnvironment(t *testing.T) {
	s := newClientTestServer(t)
	t.Setenv("HOKORA_TEST_MARKER", "present")

	var err error
	stdout := captureStdout(t, func() {
		err = cmdRun(context.Background(), s.args("--", "sh", "-c",
			`printf '%s|%s' "$HOKORA_TEST_MARKER" "$API_TOKEN"`))
	})
	if err != nil {
		t.Fatalf("cmdRun: %v", err)
	}
	if want := "present|" + testAPIToken; stdout != want {
		t.Errorf("child env = %q, want %q (parent marker + injected secret)", stdout, want)
	}
}

func TestCmdRunRequiresACommand(t *testing.T) {
	s := newClientTestServer(t)
	if err := cmdRun(context.Background(), s.args()); err == nil {
		t.Fatal("cmdRun with no command succeeded")
	}
}

// run は子プロセスの終了コードを引き継ぐ。cmdRun は os.Exit を呼ぶので、
// テストバイナリを再実行して別プロセスで観測する。
func TestCmdRunPropagatesExitCode(t *testing.T) {
	if os.Getenv("HOKORA_RUN_CHILD") == "1" {
		s := newClientTestServer(t)
		_ = cmdRun(context.Background(), s.args("--", "sh", "-c", "exit 3"))
		os.Exit(0) // ここに来たら os.Exit されていない = 失敗
	}

	//nolint:gosec // G204: 実行対象はテストバイナリ自身(os.Args[0])で固定
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run", "^TestCmdRunPropagatesExitCode$")
	cmd.Env = append(os.Environ(), "HOKORA_RUN_CHILD=1")
	err := cmd.Run()

	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Fatalf("error = %v, want an *exec.ExitError", err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("exit code = %d, want 3", exitErr.ExitCode())
	}
}

// get / run の --help は usage を stdout に出し、エラーにならない。
func TestHelpFlags(t *testing.T) {
	for _, name := range []string{"get", "run"} {
		t.Run(name, func(t *testing.T) {
			handler := map[string]func(context.Context, []string) error{
				"get": cmdGet, "run": cmdRun,
			}[name]

			var err error
			stdout := captureStdout(t, func() {
				err = handler(context.Background(), []string{"--help"})
			})
			if err != nil {
				t.Fatalf("%s --help = %v, want nil", name, err)
			}
			if stdout == "" {
				t.Errorf("%s --help printed no usage to stdout", name)
			}
		})
	}
}

// ---- 補助 ----

// captureStdout は f の実行中に os.Stdout / os.Stderr を差し替え、stdout に
// 書かれた内容を返す(stderr は捨てるが、パイプが詰まらないよう drain する)。
// プロセス全体のグローバルを触るため、これを使うテストは t.Parallel を付けない。
func captureStdout(t *testing.T, f func()) string {
	t.Helper()

	origOut, origErr := os.Stdout, os.Stderr
	t.Cleanup(func() { os.Stdout, os.Stderr = origOut, origErr })

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW

	f()

	outW.Close()
	errW.Close()
	outBytes, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if _, err := io.Copy(io.Discard, errR); err != nil {
		t.Fatalf("drain stderr: %v", err)
	}
	return string(outBytes)
}

func writeCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

func writeCredentials(t *testing.T, path string, kv map[string]string) {
	t.Helper()
	var b strings.Builder
	for k, v := range kv {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
}
