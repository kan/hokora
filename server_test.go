package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestLogger は出力先を指定したロガーを返す。
func newTestLogger(w *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}

// writeTestCert は自己署名証明書を dir/cert.pem と dir/key.pem に書く。
//
// commonName を変えると別の証明書になるので、リロードで実際に差し替わった
// ことを見分けられる。
func writeTestCert(t *testing.T, dir, commonName string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	writeFile(t, filepath.Join(dir, tlsCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, filepath.Join(dir, tlsKeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// writeFile はテスト用のファイルを書く。path は t.TempDir() 配下である。
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: t.TempDir() 配下のテスト用パスである
		t.Fatalf("write %s: %v", path, err)
	}
}

// readTestFile は t.TempDir() 配下のファイルを読む。
func readTestFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path) //nolint:gosec // G304: t.TempDir() 配下のテスト用パスである
}

// newTestTLSDir は証明書を用意したディレクトリを返す。
func newTestTLSDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	writeTestCert(t, dir, "hokora-test")
	return dir
}

// certCommonName は現在の証明書の CN を返す(どの証明書が有効かの識別用)。
func certCommonName(t *testing.T, r *certReloader) string {
	t.Helper()

	cert := r.current.Load()
	if cert == nil {
		t.Fatal("no certificate is loaded")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloaderRequiresBothFilesAtStartup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"empty directory", func(*testing.T, string) {}},
		{"certificate only", func(t *testing.T, dir string) {
			writeTestCert(t, dir, "x")
			if err := os.Remove(filepath.Join(dir, tlsKeyFile)); err != nil {
				t.Fatalf("remove key: %v", err)
			}
		}},
		{"key only", func(t *testing.T, dir string) {
			writeTestCert(t, dir, "x")
			if err := os.Remove(filepath.Join(dir, tlsCertFile)); err != nil {
				t.Fatalf("remove cert: %v", err)
			}
		}},
		{"mismatched pair", func(t *testing.T, dir string) {
			writeTestCert(t, dir, "first")
			other := t.TempDir()
			writeTestCert(t, other, "second")
			// 鍵だけ別のペアのものに差し替える(片方だけ更新された状態)。
			data, err := readTestFile(t, filepath.Join(other, tlsKeyFile))
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			writeFile(t, filepath.Join(dir, tlsKeyFile), data)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tt.setup(t, dir)

			// 起動時は落とす。証明書が無い状態で listen しても意味がない。
			if _, err := newCertReloader(dir, discardLogger()); err == nil {
				t.Fatal("newCertReloader succeeded without a usable key pair")
			}
		})
	}
}

// **リロードに失敗したら、古い有効な証明書を維持する**(AGENTS.md ルール 34)。
//
// 証明書と鍵は 2 ファイルであり、片方だけ新しい状態で SIGHUP を受けうる。
// そこで落ちると、証明書更新の失敗がサービス停止に直結する。
func TestCertReloaderKeepsTheOldCertificateOnFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestCert(t, dir, "original")

	r, err := newCertReloader(dir, discardLogger())
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	if got := certCommonName(t, r); got != "original" {
		t.Fatalf("common name = %q, want original", got)
	}

	tests := []struct {
		name   string
		broken func(t *testing.T)
	}{
		{"corrupt certificate", func(t *testing.T) {
			writeFile(t, filepath.Join(dir, tlsCertFile), []byte("not a certificate"))
		}},
		{"missing key", func(t *testing.T) {
			if err := os.Remove(filepath.Join(dir, tlsKeyFile)); err != nil {
				t.Fatalf("remove key: %v", err)
			}
		}},
		{"key from another pair", func(t *testing.T) {
			other := t.TempDir()
			writeTestCert(t, other, "other")
			data, err := readTestFile(t, filepath.Join(other, tlsKeyFile))
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			writeFile(t, filepath.Join(dir, tlsKeyFile), data)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// dir を共有するので並列にしない。
			writeTestCert(t, dir, "original")
			if err := r.Reload(); err != nil {
				t.Fatalf("reload of a valid pair: %v", err)
			}

			tt.broken(t)

			if err := r.Reload(); err == nil {
				t.Fatal("Reload succeeded with a broken key pair")
			}
			// **古い証明書が生きていること。**
			if got := certCommonName(t, r); got != "original" {
				t.Errorf("common name = %q after a failed reload, want original", got)
			}
			cert, err := r.tlsConfig().GetCertificate(&tls.ClientHelloInfo{})
			if err != nil || cert == nil {
				t.Errorf("GetCertificate = (%v, %v), want the previous certificate", cert, err)
			}
		})
	}
}

// 正しいペアに差し替えれば、実際に新しい証明書へ切り替わる。
func TestCertReloaderReplacesTheCertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestCert(t, dir, "before")

	r, err := newCertReloader(dir, discardLogger())
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	writeTestCert(t, dir, "after")
	if err := r.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := certCommonName(t, r); got != "after" {
		t.Errorf("common name = %q, want after", got)
	}
}

// ---- mux の分離(DESIGN §4.1 / AGENTS.md ルール 29) ----
//
// **listener を分けても、同じ mux を渡せば両方のポートで両方のパスが応答する。**
// 分離は「別の ServeMux を渡していること」で成立する。

func TestMuxSeparation(t *testing.T) {
	t.Parallel()

	v, _, _ := newTestVault(t)
	machine := newMachineAPI(v, discardLogger()).machineMux()
	ui := uiMuxPlaceholder()
	admin := newAdminServer(v, discardLogger()).adminMux()

	tests := []struct {
		name         string
		mux          http.Handler
		method, path string
		wantNotFound bool
	}{
		// Machine API listener は /v1 と /healthz だけを扱う。
		{"machine serves auth token", machine, http.MethodPost, "/v1/auth/token", false},
		{"machine serves secrets", machine, http.MethodGet, "/v1/secrets", false},
		{"machine serves healthz", machine, http.MethodGet, "/healthz", false},
		{"machine does not serve the ui", machine, http.MethodGet, "/ui/login", true},
		{"machine does not serve unseal", machine, http.MethodPost, "/unseal", true},
		{"machine does not serve status", machine, http.MethodGet, "/status", true},

		// **Web UI listener で /v1/auth/token と /healthz が 404**(M4 完了条件)。
		{"ui does not serve auth token", ui, http.MethodPost, "/v1/auth/token", true},
		{"ui does not serve secrets", ui, http.MethodGet, "/v1/secrets", true},
		{"ui does not serve healthz", ui, http.MethodGet, "/healthz", true},
		{"ui does not serve unseal", ui, http.MethodPost, "/unseal", true},

		// admin socket は 4 つのパスだけ。
		{"admin serves status", admin, http.MethodGet, "/status", false},
		{"admin does not serve the machine api", admin, http.MethodPost, "/v1/auth/token", true},
		{"admin does not serve healthz", admin, http.MethodGet, "/healthz", true},
		{"admin does not serve the ui", admin, http.MethodGet, "/ui/login", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			tt.mux.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil))

			if got := w.Code == http.StatusNotFound; got != tt.wantNotFound {
				t.Errorf("%s %s = %d, want not found = %v", tt.method, tt.path, w.Code, tt.wantNotFound)
			}
		})
	}
}

// ---- ミドルウェア ----

// 全レスポンスに Cache-Control: no-store が付くこと。
// ハンドラ側で書き忘れても、ミドルウェアが必ず付ける。
func TestMiddlewareSetsNoStore(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /forgot", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := withMiddleware("test", mux, discardLogger())

	for _, path := range []string{"/forgot", "/missing"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
	}
}

// パニックしても 500 を返し、内容をレスポンスに漏らさない。
func TestMiddlewareRecoversFromPanic(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-in-the-panic"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) {
		panic(secret)
	})

	var logged strings.Builder
	h := withMiddleware("test", mux, newTestLogger(&logged))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/boom", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Errorf("the response leaked the panic value: %q", w.Body.String())
	}
	// 運用ログには残る(気付けなければ直せない)。
	if !strings.Contains(logged.String(), secret) {
		t.Error("the panic was not logged")
	}
}

// ---- bind アドレス ----

// **Web UI の既定は 127.0.0.1**(AGENTS.md ルール 30)。
func TestDefaultBindAddresses(t *testing.T) {
	t.Parallel()

	if !strings.HasPrefix(DefaultUIAddr, "127.0.0.1:") {
		t.Errorf("DefaultUIAddr = %q, want it to be loopback", DefaultUIAddr)
	}
	// Machine API の到達制限は firewalld の責務なので wildcard でよい。
	if !strings.HasPrefix(DefaultMachineAddr, "0.0.0.0:") {
		t.Errorf("DefaultMachineAddr = %q", DefaultMachineAddr)
	}
	if DefaultUIAddr == DefaultMachineAddr {
		t.Error("the web ui and the machine api share a bind address")
	}
}

// 0.0.0.0 を Web UI に指定したら警告する。
func TestWarnIfWildcardBind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr     string
		wantWarn bool
	}{
		{"127.0.0.1:8443", false},
		{"10.8.0.1:8443", false},
		{"0.0.0.0:8443", true},
		{":8443", true},
		{"[::]:8443", true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()

			var logged strings.Builder
			warnIfWildcardBind(tt.addr, newTestLogger(&logged))

			if got := strings.Contains(logged.String(), "wildcard"); got != tt.wantWarn {
				t.Errorf("warned = %v, want %v (log %q)", got, tt.wantWarn, logged.String())
			}
		})
	}
}

// timeout はゼロだと無制限になる(DESIGN §7.4)。全 listener で設定されること。
func TestHTTPServerTimeouts(t *testing.T) {
	t.Parallel()

	srv := httpServerTimeouts(http.NewServeMux(), defaultWriteTimeout, discardLogger())
	timeouts := map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	}
	for name, d := range timeouts {
		if d <= 0 {
			t.Errorf("%s = %v, want a positive duration", name, d)
		}
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Errorf("MaxHeaderBytes = %d, want a positive limit", srv.MaxHeaderBytes)
	}
}

// newTestTLSClient は自己署名証明書を受け入れる HTTP クライアントを返す。
//
// **InsecureSkipVerify は使わない**(AGENTS.md ルール 31。本体に実装しない
// ものを、テストの都合で持ち込まない)。サーバーが提示する証明書を取得し、
// それを信頼する CA として積む。
func newTestTLSClient(t *testing.T, addrs serverAddrs) *http.Client {
	t.Helper()

	pool := x509.NewCertPool()
	for _, addr := range []string{addrs.Machine, addrs.UI} {
		pool.AddCert(fetchServerCert(t, addr))
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// fetchServerCert は listener が提示する証明書を 1 枚取ってくる。
func fetchServerCert(t *testing.T, addr string) *x509.Certificate {
	t.Helper()

	// ここでの接続は証明書を取得するためだけのものなので、検証を行わない。
	// 取得した証明書は上位で CA として明示的に積み直す。
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: 証明書取得のためのプローブである
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("probe %s for its certificate: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("connection type = %T, want *tls.Conn", conn)
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatalf("%s presented no certificate", addr)
	}
	return certs[0]
}

// ---- TLS の下限バージョン ----

// **TLS 1.2 未満を受け付けない。** MinVersion を設定し忘れると、Go は
// 過去の既定へは戻らないものの、設定の意図が実装から消えたことに気付けない。
// 下限は listener の設定そのものなので、値として固定する。
func TestTLSConfigMinVersion(t *testing.T) {
	t.Parallel()

	r, err := newCertReloader(newTestTLSDir(t), discardLogger())
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	if got := r.tlsConfig().MinVersion; got != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want %#x (tls 1.2)", got, tls.VersionTLS12)
	}
}

// **稼働中の listener が、リロード後の証明書を実際に提示する**(DESIGN §3.7)。
//
// certReloader の単体テストは「保持している証明書が入れ替わったか」しか見て
// いない。listener の tls.Config を組み立てる時点で証明書を焼き込んでしまう
// 実装(GetCertificate ではなく Certificates に入れる)だと、Reload しても
// handshake で出てくる証明書は古いままになる。**そこは単体テストを素通りする。**
//
// 同じ listener で、TLS 1.1 の handshake が拒否されることも確かめる。
func TestTLSListenerServesTheReloadedCertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestCert(t, dir, "before")

	certs, err := newCertReloader(dir, discardLogger())
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	srv, ln, err := startTLSListener(t.Context(), listenerSpec{
		name:    "test",
		addr:    "127.0.0.1:0",
		handler: http.NewServeMux(),
	}, certs, discardLogger())
	if err != nil {
		t.Fatalf("startTLSListener: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	addr := ln.Addr().String()
	if got := fetchServerCert(t, addr).Subject.CommonName; got != "before" {
		t.Fatalf("served common name = %q, want before", got)
	}

	// 運用側は versioned directory を作って symlink を張り替え、SIGHUP を送る。
	writeTestCert(t, dir, "after")
	if err := certs.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// **新しい接続には新しい証明書が出る。**
	if got := fetchServerCert(t, addr).Subject.CommonName; got != "after" {
		t.Errorf("served common name after reload = %q, want after", got)
	}

	// TLS 1.1 は handshake の時点で拒否される。
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true,             //nolint:gosec // G402: 下限バージョンの検査であり、証明書検証は本題ではない
		MinVersion:         tls.VersionTLS10, //nolint:gosec // G402: 古い版が拒否されることを確かめるための意図的な設定である
		MaxVersion:         tls.VersionTLS11,
	}}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Error("the listener completed a tls 1.1 handshake")
	}
}
