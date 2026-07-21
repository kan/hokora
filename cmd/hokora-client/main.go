// Command hokora-client fetches secrets from a hokora server for non-Go
// applications and migrations.
//
// アプリホストに置く**クライアント専用**バイナリである。サーバー本体
// (`hokora`)と分けることで、アプリ群には SQLite / argon2 等のサーバー依存を
// リンクせず、標準ライブラリ + sdk のみの小さなバイナリを配布する
// (依存・脆弱性面の縮小)。
//
// **Go アプリケーションは、このバイナリではなく sdk を直接 import すること。**
// `run` は環境変数へ secret を展開するため /proc/<pid>/environ から読める
// (THREAT_MODEL R5)。
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
)

const usage = `hokora-client - fetch secrets from a hokora server

Usage:
  hokora-client <command> [flags]

Commands:
  get <KEY>       print a single secret value to stdout (terminal use only)
  run -- <cmd>    run a command with secrets in its environment (migration aid;
                  secrets are readable via /proc/<pid>/environ, use the SDK in Go apps)

Go applications should import github.com/kan/hokora/sdk directly instead.
`

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "hokora-client: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "get":
		return cmdGet(ctx, rest)
	case "run":
		return cmdRun(ctx, rest)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}
