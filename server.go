package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"time"
)

// 既定の bind アドレス(DESIGN §4.1)。
const (
	// DefaultMachineAddr は Machine API の bind である。到達制限は
	// firewalld の責務であり、アプリ層では IP allowlist を実装しない
	// (AGENTS.md ルール 32)。
	DefaultMachineAddr = "0.0.0.0:9443"
	// DefaultUIAddr は Web UI の bind である。**既定は 127.0.0.1**
	// (AGENTS.md ルール 30)。VPN の IF に明示的に寄せる運用を前提とする。
	DefaultUIAddr = "127.0.0.1:8443"
)

// TLS ファイルの名前(DESIGN §3.7)。--tls-dir は
// /var/lib/hokora/tls/current のような symlink を指す。
const (
	tlsCertFile = "cert.pem"
	tlsKeyFile  = "key.pem"
)

// DefaultTLSDir は証明書ディレクトリの既定値である。
//
// certbot(**別ホスト**で動く。DESIGN §3.6)の deploy hook が versioned
// directory を作り、この symlink を rename で切り替えてから SIGHUP を送る。
const DefaultTLSDir = "/var/lib/hokora/tls/current"

// defaultWriteTimeout は応答を書き切るまでの上限である。
const defaultWriteTimeout = 15 * time.Second

// httpServerTimeouts は全ての listener に適用する timeout である。
//
// **ゼロだと無制限になる**(DESIGN §7.4)。1 箇所に集めて、listener を
// 足したときに設定漏れが起きないようにする。**admin socket もここを通す。**
// 外に置くと、片方だけ値が動いても誰も気付かない。
//
// writeTimeout だけ引数にしてあるのは、admin socket の unseal /
// rotate-master が argon2 を伴い、他より長くかかるためである。
func httpServerTimeouts(handler http.Handler, writeTimeout time.Duration, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// ---- TLS ----

// certReloader は証明書を保持し、SIGHUP でのリロードを扱う(DESIGN §3.7)。
//
// **リロードに失敗したら、古い有効な証明書を維持する**(AGENTS.md ルール 34)。
// 証明書と鍵は 2 ファイルであり、片方だけ新しい状態で SIGHUP を受けることが
// ある。そこで落ちると、証明書の更新作業がサービス停止に直結する。
//
// 運用側は versioned directory + symlink で切り替える。symlink の付け替えは
// 原子的なので、hokora が中途半端なペアを読む窓を無くせる。
type certReloader struct {
	dir     string
	logger  *slog.Logger
	current atomic.Pointer[tls.Certificate]
}

func newCertReloader(dir string, logger *slog.Logger) (*certReloader, error) {
	r := &certReloader{dir: dir, logger: logger}
	cert, err := r.load()
	if err != nil {
		// 起動時は落とす。証明書が無い状態で listen しても意味がない。
		return nil, err
	}
	r.current.Store(cert)
	return r, nil
}

// load は証明書ペアを読む。両方が揃って初めて成功する。
func (r *certReloader) load() (*tls.Certificate, error) {
	certPath := filepath.Join(r.dir, tlsCertFile)
	keyPath := filepath.Join(r.dir, tlsKeyFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load tls key pair from %s: %w", r.dir, err)
	}
	return &cert, nil
}

// Reload は証明書を読み直す。**失敗しても現行の証明書は差し替えない。**
func (r *certReloader) Reload() error {
	cert, err := r.load()
	if err != nil {
		r.logger.Error("tls reload failed; keeping the previous certificate",
			slog.String("error", err.Error()))
		return err
	}
	r.current.Store(cert)
	r.logger.Info("tls certificate reloaded", slog.String("dir", r.dir))
	return nil
}

// tlsConfig は handshake ごとに現行の証明書を引く設定を返す。
func (r *certReloader) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return r.current.Load(), nil
		},
	}
}

// ---- ミドルウェア ----

// withMiddleware はログ・パニックリカバリ・no-store を全ハンドラに被せる。
//
// **mux ごとに個別に被せる。** 共通の Handler にまとめると、mux を共有する
// 誘惑が生まれる(AGENTS.md ルール 29)。
func withMiddleware(name string, mux http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// **全レスポンスに Cache-Control: no-store**(DESIGN §8.1 / §9)。
		// ハンドラ側で書き忘れても、ここで必ず付く。
		setNoStore(w)

		defer func() {
			if rec := recover(); rec != nil {
				// パニックの内容はレスポンスに出さない。運用ログにだけ残す。
				logger.ErrorContext(r.Context(), "panic in handler",
					slog.String("listener", name),
					slog.String("path", r.URL.Path),
					slog.Any("panic", rec),
					slog.String("stack", string(debug.Stack())),
				)
				writeAPIJSON(w, http.StatusInternalServerError,
					apiErrorResponse{Error: "internal_error"}, logger)
			}
		}()

		mux.ServeHTTP(w, r)
	})
}

// ---- listener ----

// listenerSpec は 1 つの TLS listener の設定である。
type listenerSpec struct {
	name    string
	addr    string
	handler http.Handler
}

// startTLSListener は TLS listener を起動する。
func startTLSListener(ctx context.Context, spec listenerSpec, certs *certReloader, logger *slog.Logger) (*http.Server, net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", spec.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on %s (%s): %w", spec.addr, spec.name, err)
	}

	srv := httpServerTimeouts(withMiddleware(spec.name, spec.handler, logger), defaultWriteTimeout, logger)
	srv.TLSConfig = certs.tlsConfig()
	return srv, tls.NewListener(ln, srv.TLSConfig), nil
}

// warnIfWildcardBind は Web UI が 0.0.0.0 に bind された場合に警告する
// (AGENTS.md ルール 30)。
//
// **拒否はしない。** VPN の IF が起動時にまだ上がっていない構成もあるため、
// 運用の判断を奪わない。ただし「気付かないまま公開する」ことは防ぐ。
func warnIfWildcardBind(addr string, logger *slog.Logger) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	if host == "0.0.0.0" || host == "" || host == "::" {
		logger.Warn("the web ui is bound to a wildcard address; it must only be reachable from the vpn interface",
			slog.String("addr", addr))
	}
}
