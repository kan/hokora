package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/kan/hokora/sdk"
)

// clientTestServer は **本物の machineAPI** を TLS で立て、CLI(と SDK)を
// サーバー実装と往復で検証する。credentials ファイルと、自己署名証明書を
// 信頼させる CA ファイルを用意する。
type clientTestServer struct {
	credFile string
	caFile   string
}

func newClientTestServer(t *testing.T) *clientTestServer {
	t.Helper()

	// fixture が machine・grant・secret(DATABASE_URL=testSecretValue,
	// API_TOKEN=t0ken)まで用意する。now は vaultNow 固定なので、
	// トークンの発行と検証が同じ時刻になり期限切れにならない。
	f := newAPIFixture(t)

	srv := httptest.NewTLSServer(withMiddleware("machine-api", f.api.machineMux(), discardLogger()))
	t.Cleanup(srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeCertPEM(t, caFile, srv.Certificate())

	credFile := filepath.Join(t.TempDir(), "credentials")
	writeCredentials(t, credFile, map[string]string{
		"HOKORA_ADDR":          srv.URL,
		"HOKORA_CLIENT_ID":     f.clientID,
		"HOKORA_CLIENT_SECRET": f.secret,
		"HOKORA_PROJECT":       testProjectSlug,
		"HOKORA_ENV":           testEnvSlug,
	})

	return &clientTestServer{credFile: credFile, caFile: caFile}
}

// args は共通フラグ(--credentials / --ca)に続けて残りの引数を並べる。
func (s *clientTestServer) args(rest ...string) []string {
	return append([]string{"--credentials", s.credFile, "--ca", s.caFile}, rest...)
}

// captureOutput はプロセス全体の os.Stdout を差し替えるため、これを使う
// テストは並列化できない(t.Parallel を付けない)。

func TestCmdGet(t *testing.T) {
	s := newClientTestServer(t)

	var err error
	stdout, _ := captureOutput(t, func() {
		err = cmdGet(t.Context(), s.args("DATABASE_URL"))
	})
	if err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if got := strings.TrimRight(stdout, "\n"); got != testSecretValue {
		t.Errorf("stdout = %q, want %q", got, testSecretValue)
	}
}

// stdout に出るのは値そのものと改行 1 個だけであること。ファイルへ
// リダイレクトしての利用は想定しないが(コマンドコメント参照)、
// 端末での確認用途としては余分な改行が付かないことが重要である。
// TestCmdGet は TrimRight で比較するため、末尾に余分な改行が付いていても
// 検出できない。ここではより厳密に完全一致で確認する。
func TestCmdGetOutputHasExactlyOneTrailingNewline(t *testing.T) {
	s := newClientTestServer(t)

	var err error
	stdout, _ := captureOutput(t, func() {
		err = cmdGet(t.Context(), s.args("DATABASE_URL"))
	})
	if err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	want := testSecretValue + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q (value followed by exactly one newline)", stdout, want)
	}
}

func TestCmdGetUnknownKey(t *testing.T) {
	s := newClientTestServer(t)

	err := cmdGet(t.Context(), s.args("NOPE"))
	if err == nil || !strings.Contains(err.Error(), "NOPE") {
		t.Fatalf("error = %v, want it to name the missing key", err)
	}
}

func TestCmdGetRejectsUntrustedTLS(t *testing.T) {
	s := newClientTestServer(t)

	// --ca を渡さなければ自己署名証明書は信頼されず、Fetch は失敗する。
	// **InsecureSkipVerify 相当が無いこと**の裏取り。
	err := cmdGet(t.Context(), []string{"--credentials", s.credFile, "DATABASE_URL"})
	if err == nil {
		t.Fatal("cmdGet trusted an unknown CA")
	}
}

// --ca の既定値は $HOKORA_CA_FILE から取れる(--ca フラグ自体は省略)。
// これを検証するには、フラグを渡さない状態で TLS 検証が実際にこの CA を
// 使って成功することを示す必要がある(TestCmdGetRejectsUntrustedTLS は
// 逆側 — CA を全く渡さない場合の失敗 — を確認している)。
func TestClientOptionsCADefaultFromEnv(t *testing.T) {
	s := newClientTestServer(t)

	t.Setenv(envCAFile, s.caFile)

	// --ca は渡さない。$HOKORA_CA_FILE 経由でのみ CA を伝える。
	var err error
	stdout, _ := captureOutput(t, func() {
		err = cmdGet(t.Context(), []string{"--credentials", s.credFile, "DATABASE_URL"})
	})
	if err != nil {
		t.Fatalf("cmdGet with $%s set but no --ca flag: %v", envCAFile, err)
	}
	if got := strings.TrimRight(stdout, "\n"); got != testSecretValue {
		t.Errorf("stdout = %q, want %q", got, testSecretValue)
	}
}

// --addr が credentials ファイルの HOKORA_ADDR を上書きすることを、
// ファイル側にわざと到達不能なアドレスを書いて確かめる。上書きが効いて
// いなければ、--addr を渡しても接続に失敗し続けるはずである。
func TestClientOptionsOverrideAddr(t *testing.T) {
	f := newAPIFixture(t)
	srv := httptest.NewTLSServer(withMiddleware("machine-api", f.api.machineMux(), discardLogger()))
	t.Cleanup(srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeCertPEM(t, caFile, srv.Certificate())

	// 誰も listen していないポートを用意する(bind してすぐ閉じるので、
	// 環境のポート割り当てに依存せず「接続拒否」を再現できる)。
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	unreachable := "https://" + ln.Addr().String()
	if closeErr := ln.Close(); closeErr != nil {
		t.Fatalf("close listener: %v", closeErr)
	}

	credFile := filepath.Join(t.TempDir(), "credentials")
	writeCredentials(t, credFile, map[string]string{
		"HOKORA_ADDR":          unreachable,
		"HOKORA_CLIENT_ID":     f.clientID,
		"HOKORA_CLIENT_SECRET": f.secret,
		"HOKORA_PROJECT":       testProjectSlug,
		"HOKORA_ENV":           testEnvSlug,
	})

	// 対照: ファイルの誤ったアドレスがそのまま使われ、失敗すること。
	if err := cmdGet(t.Context(), []string{"--credentials", credFile, "--ca", caFile, "DATABASE_URL"}); err == nil {
		t.Fatal("cmdGet succeeded despite an unreachable HOKORA_ADDR in the credentials file")
	}

	// --addr がファイルの値を上書きし、本物のサーバーに到達すること。
	var getErr error
	stdout, _ := captureOutput(t, func() {
		getErr = cmdGet(t.Context(), []string{
			"--credentials", credFile, "--ca", caFile, "--addr", srv.URL, "DATABASE_URL",
		})
	})
	if getErr != nil {
		t.Fatalf("cmdGet with --addr override: %v", getErr)
	}
	if got := strings.TrimRight(stdout, "\n"); got != testSecretValue {
		t.Errorf("stdout = %q, want %q", got, testSecretValue)
	}
}

// --project / --env が credentials ファイルの値を上書きすることを、
// わざと grant のない project / env を指定してサーバーに forbidden を
// 返させることで確認する。上書きが効いていなければファイルの正しい値
// (myapp/prod)が使われ続け、成功してしまうはずである。
func TestClientOptionsOverrideProjectAndEnv(t *testing.T) {
	s := newClientTestServer(t)

	tests := []struct {
		name string
		flag string
		val  string
	}{
		{"project", "--project", "no-such-project"},
		{"env", "--env", "no-such-env"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmdGet(t.Context(), s.args(tt.flag, tt.val, "DATABASE_URL"))
			if !errors.Is(err, sdk.ErrForbidden) {
				t.Fatalf("cmdGet with %s %s = %v, want sdk.ErrForbidden (proves the flag reached the server)",
					tt.flag, tt.val, err)
			}
		})
	}
}

// loadCAPool: 存在しないファイル。
func TestLoadCAPoolMissingFile(t *testing.T) {
	_, err := loadCAPool(filepath.Join(t.TempDir(), "does-not-exist.pem"))
	if err == nil {
		t.Fatal("loadCAPool with a nonexistent file succeeded")
	}
}

// loadCAPool: ファイルは読めるが PEM 証明書を含まない場合。
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

	// 子プロセスで環境変数を stdout に出させ、secret が展開されたか見る。
	var err error
	stdout, _ := captureOutput(t, func() {
		err = cmdRun(t.Context(), s.args("--", "sh", "-c", `printf '%s' "$DATABASE_URL"`))
	})
	if err != nil {
		t.Fatalf("cmdRun: %v", err)
	}
	if stdout != testSecretValue {
		t.Errorf("child saw DATABASE_URL = %q, want %q", stdout, testSecretValue)
	}
}

// 子プロセスは注入された secret だけでなく、**親プロセスの環境も**
// 引き継ぐ(childEnv は os.Environ() をベースに secret を追加する実装。
// コメント「子プロセスの環境に secret を足す。親の環境は変更しない。」の
// 「足す」側の裏取り)。
func TestCmdRunInheritsParentEnvironment(t *testing.T) {
	s := newClientTestServer(t)

	t.Setenv("HOKORA_TEST_PARENT_MARKER", "parent-value-xyz")

	var err error
	stdout, _ := captureOutput(t, func() {
		err = cmdRun(t.Context(), s.args("--", "sh", "-c",
			`printf 'marker=%s secret=%s' "$HOKORA_TEST_PARENT_MARKER" "$DATABASE_URL"`))
	})
	if err != nil {
		t.Fatalf("cmdRun: %v", err)
	}
	want := "marker=parent-value-xyz secret=" + testSecretValue
	if stdout != want {
		t.Errorf("child env = %q, want %q (parent env var + injected secret both present)", stdout, want)
	}
}

func TestCmdRunRequiresACommand(t *testing.T) {
	s := newClientTestServer(t)

	if err := cmdRun(t.Context(), s.args()); err == nil {
		t.Fatal("cmdRun with no command succeeded")
	}
}

// run は子プロセスの終了コードを引き継ぐ。cmdRun は os.Exit を呼ぶので、
// テストバイナリを再実行して別プロセスで観測する(標準的な手法)。
func TestCmdRunPropagatesExitCode(t *testing.T) {
	if os.Getenv("HOKORA_RUN_CHILD") == "1" {
		s := newClientTestServer(t)
		_ = cmdRun(t.Context(), s.args("--", "sh", "-c", "exit 3"))
		// ここに到達したら os.Exit が呼ばれていない = 失敗。
		os.Exit(0)
	}

	//nolint:gosec // G204: 実行対象はテストバイナリ自身(os.Args[0])で固定
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestCmdRunPropagatesExitCode$")
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

// -h / --help はエラーではない。usage を stdout に出して nil を返す
// (flag.ErrHelp の扱いが get/run 双方の cmdXxx 内で自己完結しているため、
// main_test.go の TestRunHelpVariantsSucceedAndPrintUsageToStdout はここを
// 通らない。get/run 固有の --help 経路として別途確認する)。
func TestCmdGetHelp(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() {
		err = cmdGet(t.Context(), []string{"--help"})
	})
	if err != nil {
		t.Fatalf("cmdGet(--help) = %v, want nil", err)
	}
	if !strings.Contains(stdout, "-addr") {
		t.Errorf("stdout = %q, want it to list the flags (e.g. -addr)", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

func TestCmdRunHelp(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() {
		err = cmdRun(t.Context(), []string{"--help"})
	})
	if err != nil {
		t.Fatalf("cmdRun(--help) = %v, want nil", err)
	}
	if !strings.Contains(stdout, "-addr") {
		t.Errorf("stdout = %q, want it to list the flags (e.g. -addr)", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

// ---- 補助 ----

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
