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

// cmdBackup は稼働中の DB から暗号文のみの整合スナップショットを 1 ファイルに
// 書き出す(DESIGN の Phase 2「VACUUM INTO によるオンラインバックアップ」)。
//
// **この操作は Vault に一切触れない。** DB が保持するのは暗号文だけなので、
// バックアップに DEK も MK も要らない。したがって seal 状態でも、`hokora serve`
// が稼働中でも実行できる(SQLite は WAL で複数プロセスの並行アクセスを許す)。
// これが offline 手順(seal → 停止 → tar)を置き換える利点である ── 停止も
// 再 unseal も要らず、`-wal` / `-shm` の取りこぼしも起きない。
//
// **監査ログには記録しない。** 理由は 3 つある:
//  1. VACUUM は暗黙のトランザクションの外でしか実行できないため、fail closed の
//     監査(本体と同一トランザクションで確定させる。THREAT_MODEL §10.4)を
//     そもそも成立させられない。
//  2. この操作を実行できる主体(hokora ユーザー + ファイルへの到達権)は、
//     既に `cp /var/lib/hokora/hokora.db` で暗号文をそのまま持ち出せる。
//     backup コマンドは新しい能力を与えないので、記録しても抑止にならない。
//  3. offline 手順(サーバー停止中の tar)も監査されない。一貫させる。
//
// **生成物はやはり全 secret の暗号文である。** ファイルのパーミッションを厳格に
// し、MK とは別の場所へ保管すること(OPERATIONS §9.1)。復号には「このファイル
// + その時点で有効だった MK」の両方が要る。
func cmdBackup(ctx context.Context, args []string) (err error) {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	// エラーの体裁は main に一本化する(cmd_init.go と同じ理由)。
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", DefaultDBPath, "path to the SQLite database file")
	out := flags.String("out", "", "path to write the backup to (required; must not already exist)")
	if handled, err := parseFlags(flags, args); handled {
		return err
	}
	if *out == "" {
		return errors.New("backup: --out is required")
	}

	// 先に元 DB を開く。ここで失敗しても出力先はまだ作らない。
	// OpenStore を通すのは、DB に触る経路を 1 箇所へ集約してスキーマ版の不一致
	// (バイナリと DB の取り違え)を弾くためである(store.go)。DSN の busy_timeout
	// により、稼働中サーバーが書き込みロックを握る瞬間に当たっても即エラーにせず待つ。
	store, err := OpenStore(ctx, *dbPath)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	defer closeStore(store, &err)

	// 出力先を 0600 で先に作る(理由は prepareBackupDest 参照)。以降の失敗は、
	// この空ファイルを取り除いてから返す。
	if err := prepareBackupDest(*out); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	// VACUUM INTO は WAL 上の未チェックポイント分も含む、読み取りトランザクション
	// 時点の整合スナップショットを、随伴ファイル無しの単一 DB として、先に作った
	// 0600 の空ファイルへ書き出す(既存ファイルのパーミッションは保たれる)。
	// **パスはプレースホルダで束縛する**(文字列連結で組むと、パスに引用符が
	// 混ざったときに壊れる/注入経路になる)。
	if _, err := store.DB().ExecContext(ctx, `VACUUM INTO ?`, *out); err != nil {
		return errors.Join(fmt.Errorf("backup: write snapshot: %w", err), removeBackupArtifact(*out))
	}

	// 作成時に 0600 で確定しているが、念のため締め直す(将来 driver が対象を
	// 作り直す実装になった場合の保険。通常は no-op)。
	if err := os.Chmod(*out, dbFileMode); err != nil {
		return errors.Join(fmt.Errorf("backup: chmod snapshot: %w", err), removeBackupArtifact(*out))
	}

	// 「書けた」と「開ける」は違う。生成物を読み取り専用で開き直し、本バイナリと
	// 同じスキーマ版の DB として読めることだけ確かめる。**これは復元テストの
	// 代わりではない**(復元して実際に unseal・復号できることは別途必須。
	// OPERATIONS §9.2)。ここで捕らえるのは、切り詰め・破損など「そもそも
	// SQLite として開けない」壊れ方だけである。
	if err := verifyBackup(ctx, *out); err != nil {
		return errors.Join(fmt.Errorf("backup: %w", err), removeBackupArtifact(*out))
	}

	reportBackup(*out)
	return nil
}

// prepareBackupDest は出力先の親ディレクトリを用意し、出力ファイルを 0600 で
// 先に作る。
//
// **ファイルを 0600 で先に作るのが肝心である。** 作成を VACUUM INTO に任せると
// プロセスの umask 依存のモードで作られ、その後 chmod で締めるまでの一瞬、全
// secret の暗号文が他ユーザーから読めうる(親ディレクトリが緩い場所を --out に
// 指定された場合)。作成モードは umask で下がることはあっても上がらないので、
// 0600 で作れば作成時点から他者に読めない。VACUUM INTO は 0 バイトの空ファイルを
// 空の DB として受け入れ、既存ファイルのパーミッションを保ったまま書き込む。
//
// **既存の出力先は上書きしない**(O_EXCL)。バックアップを取り違えて既存の
// バックアップを潰す事故を防ぐ。O_EXCL は「存在確認 → 作成」の間の競合も同時に
// 閉じる(VACUUM INTO 自身も既存ファイルを拒否するが、その際のエラーは "file is
// not a database" と分かりにくい)。
func prepareBackupDest(out string) error {
	// 親ディレクトリは 0700 で用意する(cmd_init.go の ensureDBFile と同じ方針)。
	if err := os.MkdirAll(filepath.Dir(out), dbDirMode); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// out は運用者が --out で与えるパスであり、外部からの入力ではない。
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, dbFileMode) //nolint:gosec // G304
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite it", out)
		}
		return fmt.Errorf("create output file: %w", err)
	}
	if err := f.Close(); err != nil {
		return errors.Join(fmt.Errorf("create output file: %w", err), removeBackupArtifact(out))
	}
	return nil
}

// verifyBackup はバックアップを読み取り専用で開き、本バイナリと同じスキーマ版の
// DB として読めることを確かめる。
//
// **OpenStoreReadOnly を通す**(mode=ro でスナップショットを書き換えず、
// `-wal` / `-shm` の随伴ファイルも作らない。store.go)。ここで捕らえるのは
// 切り詰め・破損など「そもそも SQLite として開けない」壊れ方だけである。
func verifyBackup(ctx context.Context, out string) (err error) {
	store, err := OpenStoreReadOnly(ctx, out)
	if err != nil {
		return fmt.Errorf("verify snapshot: %w", err)
	}
	defer closeStore(store, &err)
	return nil
}

// removeBackupArtifact は失敗時に書きかけの出力を取り除く。
//
// 既に消えている(そもそも作られなかった)場合は成功扱いにする。消せなかった
// 場合だけ、元のエラーへ合流させるためにエラーを返す。
func removeBackupArtifact(out string) error {
	if err := os.Remove(out); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove incomplete snapshot %s: %w", out, err)
	}
	return nil
}

// reportBackup は結果を stderr に出す。
//
// バックアップの中身は機密(全 secret の暗号文)なので、stdout はパスだけに
// 保つ ── スクリプトからパスを拾いやすくし、注意書きが混ざらないようにする。
func reportBackup(out string) {
	fmt.Println(out)
	fmt.Fprintf(os.Stderr,
		"wrote an encrypted backup to %s\n"+
			"this file contains the ciphertext of every secret. keep it 0600, "+
			"and store it separately from the master key.\n"+
			"restoring it needs both this file and the master key that was in "+
			"effect when it was taken. verify a real restore before you rely on it "+
			"(see OPERATIONS.md).\n",
		out)
}
