package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// tokenSweepInterval はトークンの掃除間隔である。
//
// **これは期限判定ではない。** 期限は Lookup が毎回検査する(DESIGN §7.1)。
// sweep に期限判定を任せると、この間隔のぶんトークンが余分に使えてしまう。
const tokenSweepInterval = time.Minute

// shutdownTimeout は graceful shutdown の待ち時間である。
const shutdownTimeout = 10 * time.Second

// serveOptions は runServer の設定である。テストから差し替えられるように
// 依存を引数で受け取る。
type serveOptions struct {
	dbPath      string
	adminSocket string
	machineAddr string
	uiAddr      string
	tlsDir      string

	// lockMemory は mlockall を実行する。テストでは差し替える
	// (テストプロセスの RLIMIT_MEMLOCK は通常 8 MB 程度しかない)。
	lockMemory func() error

	// ready は全ての listener が起動した直後に、実際の bind アドレスとともに
	// 呼ばれる(テスト用)。ポート 0 で起動したときの実ポートを知る唯一の手段。
	ready func(serverAddrs)

	// reload は証明書のリロード契機を通知する。既定では SIGHUP。
	// テストでは任意のタイミングで発火させる。
	reload func(ctx context.Context) <-chan struct{}

	logger *slog.Logger
}

// cmdServe はサーバーを起動する。**起動時は必ず sealed である。**
func cmdServe(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", DefaultDBPath, "path to the SQLite database file")
	socket := flags.String("admin-socket", DefaultAdminSocket, "path to the admin unix socket")
	machineAddr := flags.String("machine-addr", DefaultMachineAddr, "bind address for the machine api")
	uiAddr := flags.String("ui-addr", DefaultUIAddr, "bind address for the web ui (must stay on the vpn interface)")
	tlsDir := flags.String("tls-dir", DefaultTLSDir, "directory holding cert.pem and key.pem (a symlink to a versioned directory)")
	if handled, err := parseFlags(flags, args); handled {
		return err
	}

	// SIGINT / SIGTERM で graceful shutdown する。
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runServer(ctx, serveOptions{
		dbPath:      *dbPath,
		adminSocket: *socket,
		machineAddr: *machineAddr,
		uiAddr:      *uiAddr,
		tlsDir:      *tlsDir,
		lockMemory:  lockMemory,
		reload:      notifySIGHUP,
	})
}

// runServer は 3 つの口を開き、ctx が終わるまで待つ。
//
//	Machine API : machineAddr、machineMux、TLS
//	Web UI      : uiAddr(既定は 127.0.0.1)、uiMux、TLS
//	admin       : unix socket 0600、adminMux
//
// **3 つとも独立した ServeMux を渡す**(AGENTS.md ルール 29)。listener を
// 分けても同じ mux を渡せば、両方のポートで両方のパスが応答してしまう。
// 分離は最後まで貫かないと意味がない。
func runServer(ctx context.Context, opts serveOptions) (err error) {
	logger := opts.logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	// **mlockall は最初に行う。** 失敗したら起動しない(DESIGN §4.2)。
	// swap に鍵が出る状態で「動いてはいる」のが最悪である。
	if err := opts.lockMemory(); err != nil {
		return err
	}

	store, err := OpenStore(ctx, opts.dbPath)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)

	vault := NewVault(store.DB(), logger, defaultMaxTokens)

	certs, err := newCertReloader(opts.tlsDir, logger)
	if err != nil {
		return err
	}

	// **Web UI の bind が wildcard なら警告する**(AGENTS.md ルール 30)。
	warnIfWildcardBind(opts.uiAddr, logger)

	servers, addrs, serveErr, err := startListeners(ctx, opts, vault, certs, logger)
	if err != nil {
		return err
	}

	logger.InfoContext(ctx, "hokora started (sealed)",
		slog.String("machine_addr", opts.machineAddr),
		slog.String("ui_addr", opts.uiAddr),
		slog.String("admin_socket", opts.adminSocket),
		slog.String("db", opts.dbPath),
	)
	if opts.ready != nil {
		opts.ready(addrs)
	}

	sweep := time.NewTicker(tokenSweepInterval)
	defer sweep.Stop()

	reload := opts.reload
	if reload == nil {
		reload = notifySIGHUP
	}
	reloadCh := reload(ctx)

	for {
		select {
		case <-ctx.Done():
			return shutdown(servers, vault, logger)
		case err := <-serveErr:
			// listener が落ちたら、他も畳んで終わる。片肺で動き続けない。
			return errors.Join(err, shutdown(servers, vault, logger))
		case <-reloadCh:
			// **失敗しても起動は続ける。** 古い証明書が有効なままである方が、
			// 証明書更新の失敗でサービスを落とすより安全である。
			// Reload 自身が失敗を運用ログに出す。
			if err := certs.Reload(); err != nil {
				continue
			}
		case now := <-sweep.C:
			vault.SweepTokens(now)
		}
	}
}

// serverAddrs は実際に bind されたアドレスである(ポート 0 指定時の実ポート)。
type serverAddrs struct {
	Machine string
	UI      string
}

// startListeners は 3 つの口を開く。**どれか 1 つでも失敗したら全て閉じる。**
func startListeners(ctx context.Context, opts serveOptions, vault *Vault, certs *certReloader, logger *slog.Logger) (servers []*http.Server, addrs serverAddrs, serveErr chan error, err error) {
	serveErr = make(chan error, 3)
	defer func() {
		if err != nil {
			// 起動途中で失敗した場合、既に開いた口を閉じる。ここでの
			// Close の失敗は、返そうとしている起動エラーより情報量が無い。
			for _, srv := range servers {
				if cerr := srv.Close(); cerr != nil {
					logger.Warn("could not close a listener while aborting startup",
						slog.String("error", cerr.Error()))
				}
			}
		}
	}()

	// **Machine API と Web UI は、それぞれ独立した mux を持つ。**
	// ここで同じ mux を 2 つ渡すと、両方のポートで両方のパスが応答する
	// (AGENTS.md ルール 29 と、その元になった教訓)。
	specs := []listenerSpec{
		{name: "machine-api", addr: opts.machineAddr, handler: newMachineAPI(vault, logger).machineMux()},
		{name: "web-ui", addr: opts.uiAddr, handler: uiMuxPlaceholder()},
	}
	bound := make([]string, len(specs))
	for i, spec := range specs {
		srv, ln, err := startTLSListener(ctx, spec, certs, logger)
		if err != nil {
			return servers, addrs, serveErr, err
		}
		servers = append(servers, srv)
		bound[i] = ln.Addr().String()
		go serveUntilClosed(srv, ln, spec.name, serveErr)
	}
	addrs = serverAddrs{Machine: bound[0], UI: bound[1]}

	// admin socket は TLS を張らない。unix socket のパーミッション(0600)と
	// 親ディレクトリ(0700)が境界である。
	adminLn, err := listenAdminSocket(ctx, opts.adminSocket)
	if err != nil {
		return servers, addrs, serveErr, err
	}
	adminSrv := newAdminServer(vault, logger).newAdminHTTPServer()
	servers = append(servers, adminSrv)
	go serveUntilClosed(adminSrv, adminLn, "admin", serveErr)

	return servers, addrs, serveErr, nil
}

// serveUntilClosed は Serve の終了を 1 本のチャネルへ集約する。
func serveUntilClosed(srv *http.Server, ln net.Listener, name string, serveErr chan<- error) {
	// Serve は Shutdown / Close 時に ErrServerClosed を返す。正常終了である。
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		serveErr <- fmt.Errorf("%s listener: %w", name, err)
	}
}

// notifySIGHUP は SIGHUP を受け取るチャネルを返す(証明書のリロード契機)。
func notifySIGHUP(ctx context.Context) <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)

	out := make(chan struct{}, 1)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				select {
				case out <- struct{}{}:
				default: // 直前のリロードがまだ処理されていない。落としてよい。
				}
			}
		}
	}()
	return out
}

// shutdown は全ての listener を閉じ、DEK を消してから戻る。
func shutdown(servers []*http.Server, vault *Vault, logger *slog.Logger) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var err error
	for _, srv := range servers {
		err = errors.Join(err, srv.Shutdown(shutdownCtx))
	}

	// **終了時は必ず seal する。** プロセスが消えればメモリも消えるが、
	// 明示的にゼロクリアしておく方が、コアダンプ等で残る窓が小さい。
	// seal は fail open なので、監査 DB が壊れていても止まらない。
	vault.Seal(shutdownCtx, socketAudit(time.Now()))
	logger.Info("hokora stopped (sealed)")

	if err != nil {
		return fmt.Errorf("shutdown listeners: %w", err)
	}
	return nil
}
