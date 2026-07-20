// Command hokora is a minimal secret management server for a single organization.
//
// 脅威モデルと設計は docs/THREAT_MODEL.md および docs/DESIGN.md を参照。
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// errNotImplemented は、後続マイルストーンで実装するサブコマンドが返す。
var errNotImplemented = errors.New("not implemented yet")

const usage = `hokora - minimal secret management server

Usage:
  hokora <command> [flags]

Server commands:
  init            initialize the database
  gen-key         generate a new master key and print it (does not touch the database)
  serve           run the server (starts sealed)
  unseal --stdin  unseal the server (master key is read from stdin)
  seal            seal the server
  status          show the server status
  rotate-master --stdin
                  rotate the master key (current and new key are read from stdin)

Client commands:
  get <KEY>       print a single secret value to stdout
  run -- <cmd>    run a command with secrets in its environment (migration aid)
`

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "hokora: %v\n", err)
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
	case "init":
		return cmdInit(ctx, rest)
	case "gen-key":
		return cmdGenKey(ctx, rest)
	case "serve":
		return cmdServe(ctx, rest)
	case "unseal":
		return cmdUnseal(ctx, rest)
	case "seal":
		return cmdSeal(ctx, rest)
	case "status":
		return cmdStatus(ctx, rest)
	case "rotate-master":
		return cmdRotateMaster(ctx, rest)
	case "get", "run":
		return fmt.Errorf("%s: %w", cmd, errNotImplemented)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}
