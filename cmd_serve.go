package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
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

	// lockMemory は mlockall を実行する。テストでは差し替える
	// (テストプロセスの RLIMIT_MEMLOCK は通常 8 MB 程度しかない)。
	lockMemory func() error

	// ready は admin socket が listen 状態になった直後に呼ばれる(テスト用)。
	ready func()

	logger *slog.Logger
}

// cmdServe はサーバーを起動する。**起動時は必ず sealed である。**
func cmdServe(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", DefaultDBPath, "path to the SQLite database file")
	socket := flags.String("admin-socket", DefaultAdminSocket, "path to the admin unix socket")
	if handled, err := parseFlags(flags, args); handled {
		return err
	}

	// SIGINT / SIGTERM で graceful shutdown する。
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runServer(ctx, serveOptions{
		dbPath:      *dbPath,
		adminSocket: *socket,
		lockMemory:  lockMemory,
	})
}

// runServer は admin socket を開き、ctx が終わるまで待つ。
//
// M3 の時点では admin socket のみを開く。Machine API listener(M4)と
// Web UI listener(M5)は、**それぞれ独立した ServeMux** を持つものとして
// 後から追加する(AGENTS.md ルール 29)。
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
	admin := newAdminServer(vault, logger)

	ln, err := listenAdminSocket(ctx, opts.adminSocket)
	if err != nil {
		return err
	}

	srv := admin.newAdminHTTPServer()
	serveErr := make(chan error, 1)
	go func() {
		// Serve は Shutdown 時に ErrServerClosed を返す。これは正常終了である。
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	logger.InfoContext(ctx, "hokora started (sealed)",
		slog.String("admin_socket", opts.adminSocket),
		slog.String("db", opts.dbPath),
	)
	if opts.ready != nil {
		opts.ready()
	}

	sweep := time.NewTicker(tokenSweepInterval)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			return shutdown(srv, vault, logger)
		case err := <-serveErr:
			if err != nil {
				return fmt.Errorf("admin socket: %w", err)
			}
			return nil
		case now := <-sweep.C:
			vault.SweepTokens(now)
		}
	}
}

// shutdown は listener を閉じ、DEK を消してから戻る。
func shutdown(srv *http.Server, vault *Vault, logger *slog.Logger) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	err := srv.Shutdown(shutdownCtx)

	// **終了時は必ず seal する。** プロセスが消えればメモリも消えるが、
	// 明示的にゼロクリアしておく方が、コアダンプ等で残る窓が小さい。
	// seal は fail open なので、監査 DB が壊れていても止まらない。
	vault.Seal(shutdownCtx, socketAudit(time.Now()))
	logger.Info("hokora stopped (sealed)")

	if err != nil {
		return fmt.Errorf("shutdown admin socket: %w", err)
	}
	return nil
}
