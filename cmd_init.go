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
	"time"
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
// DB を作り、スキーマを適用し、keyring を作る。**生成した MK は一度だけ
// stdout に表示され、以後どこにも残らない**(AGENTS.md ルール 11)。
// 初期 admin ユーザーの作成は Web UI(M5)の成果物であり、そちらで追加する。
//
// 既存の DB に対しては、未適用のスキーマを当てるだけで keyring は触らない。
func cmdInit(ctx context.Context, args []string) (err error) {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	// エラーの体裁は main に一本化する。flag に出力させると、main が返り値の
	// エラーを出すのと合わせて同じ文言が二度出る。
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", DefaultDBPath, "path to the SQLite database file")
	if handled, err := parseFlags(flags, args); handled {
		return err
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
	defer closeStore(store, &err)

	if err := Migrate(ctx, store.DB()); err != nil {
		return err
	}

	// スキーマ適用後に keyring を作る。初期 admin ユーザーの作成は Web UI
	// (M5)の成果物なので、そちらで追加する。
	if err := ensureKeyring(ctx, store, time.Now()); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "initialized %s\n", *dbPath)
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

// cmdGenKey は新しいマスターキーを生成して表示する。**DB には触らない。**
//
// 生成と DB 更新を分けるのは、「生成 → DB 更新 → 1Password 保存前にクラッシュ」
// で全データが復旧不能になる事故を防ぐためである(AGENTS.md ルール 18)。
// 人間が保存を確認してから `hokora rotate-master` を実行する。
func cmdGenKey(_ context.Context, args []string) error {
	flags := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if handled, err := parseFlags(flags, args); handled {
		return err
	}

	mk, err := GenerateKey()
	if err != nil {
		return err
	}
	defer Zero(mk)

	// 鍵は stdout に、それ以外は stderr に出す。パイプで 1Password 等へ
	// 渡したときに、説明文が鍵に混ざらないようにする。
	printMasterKey(mk)
	return nil
}

// printMasterKey は MK を一度だけ表示する。
//
// **MK はディスクに書かない**(AGENTS.md ルール 11)。ここで控えなければ
// 復旧手段は無い、ということを運用者に伝える。
func printMasterKey(mk []byte) {
	fmt.Println(EncodeMasterKey(mk))
	fmt.Fprintln(os.Stderr,
		"store this master key in the organization's password manager now. "+
			"hokora never writes it to disk and cannot show it again.")
}

// ensureKeyring は keyring が無ければ作り、生成した MK を表示する。
//
// 既に keyring がある DB では **何もしない。** 上書きすると既存の DEK を失い、
// 全ての secret が復号不能になる。
func ensureKeyring(ctx context.Context, store *Store, now time.Time) error {
	switch _, err := LoadKeyring(ctx, store.DB()); {
	case err == nil:
		return nil
	case !errors.Is(err, ErrKeyringMissing):
		return err
	}

	mk, err := GenerateKey()
	if err != nil {
		return err
	}
	defer Zero(mk)

	kr, dek, err := NewKeyring(mk, now)
	if err != nil {
		return err
	}
	// DEK はここでは保持しない。unseal のたびに MK から復元する。
	Zero(dek)

	if err := InsertKeyring(ctx, store.DB(), kr); err != nil {
		return err
	}
	printMasterKey(mk)
	return nil
}
