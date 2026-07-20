package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultDBPath は DB ファイルの既定の位置である。
// systemd unit の ReadWritePaths=/var/lib/hokora と対応する(DESIGN §4.3)。
const DefaultDBPath = "/var/lib/hokora/hokora.db"

// dbFileMode / dbDirMode は DB ファイルとその親ディレクトリのパーミッション。
// DB には暗号化された secret と監査ログが入る。SQLite は WAL / SHM ファイルを
// 本体ファイルと同じモードで作るため、本体を 0600 で作れば付随ファイルも従う。
const (
	dbFileMode os.FileMode = 0o600
	dbDirMode  os.FileMode = 0o700
)

// cmdInit は DB ファイルを作成し、スキーマを適用する。
//
// M1 の範囲では DB の初期化のみを行う。マスターキーの生成(keyring の作成)と
// 初期 admin ユーザーの作成は、それぞれ暗号レイヤー(M2/M3)と Web UI(M5)の
// 成果物であり、そちらで追加する。
func cmdInit(ctx context.Context, args []string) (err error) {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	// エラーの体裁は main に一本化する。flag に出力させると、main が返り値の
	// エラーを出すのと合わせて同じ文言が二度出る。
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", DefaultDBPath, "path to the SQLite database file")
	if err := flags.Parse(args); err != nil {
		// -h はエラーではない。usage を stdout に出して正常終了する。
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stdout)
			flags.Usage()
			return nil
		}
		return fmt.Errorf("init: %w", err)
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	if err := ensureDBFile(*dbPath); err != nil {
		return err
	}

	// init はスキーマ未適用の DB を扱う唯一のコマンドなので、バージョン検査を
	// 行わない openDatabase を使う。
	store, err := openDatabase(ctx, *dbPath)
	if err != nil {
		return err
	}
	// Close の失敗は WAL のチェックポイント漏れ等を示すので、握りつぶさない。
	defer func() {
		if cerr := store.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close database: %w", cerr)
		}
	}()

	if err := Migrate(ctx, store.DB()); err != nil {
		return err
	}

	fmt.Printf("initialized %s\n", *dbPath)
	return nil
}

// ensureDBFile は親ディレクトリと DB ファイルを、他ユーザーから読めない
// パーミッションで用意する。既存のファイルには触れない。
func ensureDBFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), dbDirMode); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}

	// path は運用者が --db で与えるパスであり、外部からの入力ではない。
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, dbFileMode) //nolint:gosec // G304
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// 既存 DB への再実行は、未適用のスキーマを当てるだけにする。
			return nil
		}
		return fmt.Errorf("create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	return nil
}
