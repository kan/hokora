package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// 刈り込みが受け付ける --keep-days の範囲である。
//
// **どこまで残すかは運用が決める**(THREAT_MODEL §10.7)。hokora が決めるのは
// 下限だけである。打ち間違い(--keep-days 3)で直近の記録まで消す事故を防ぐ。
//
// 上限は、日数を time.Duration に直すときの桁あふれを防ぐためにある。あふれた
// 値は小さな正の期間に化けることがあり(213540 日が約 36 日になる)、そのまま
// 通すと「全部残す」つもりの指定で、直近以外が消える。
const (
	minAuditKeepDays = 30
	maxAuditKeepDays = 36500
	minAuditKeep     = minAuditKeepDays * 24 * time.Hour
)

// auditPruneChunkRows は、1 回に読み進める行数の目安である。
//
// 刈り込みは稼働中のサーバーと同じ DB に書く。SQLite の書き込みは 1 つずつ
// なので、1 回で全てを消すと、その間 secret の読み取り(監査の INSERT が要る。
// fail closed)が待たされる。小さく分けて、合間に譲る。
const auditPruneChunkRows = 2000

// auditPruneYield は、削除の合間に書き込みを譲る時間である。
// SQLite のロックは順番待ちを保証しないので、明示的に空ける。
const auditPruneYield = 10 * time.Millisecond

// auditPrunableSQL は、刈り込みの対象になる行の条件である(期間と id の範囲は
// 別に足す)。
//
// **machine が定常的に出す、成功の記録だけを対象にする。** 本番の実測では、
// これが行の 99.9% を占める(secret.read の成功 93%、auth.machine の成功 7%)。
// 次のものは、期間にかかわらず残す。
//
//   - 失敗(拒否された読み取り、認証の失敗、レート制限)
//   - 人の操作(reveal、secret の書き込みと削除、credential の再発行、grant、
//     unseal / seal、ログイン、各種の作成と削除)
//   - 刈り込みの記録(audit.prune)
//
// どれも量は少なく(80 日で約 150 行)、調査で要るのはこちらである。
//
// **「machine の」を条件に入れてある**(actor_machine_id IS NOT NULL)。操作の
// 名前だけで選ぶと、将来、人や admin socket が同じ操作を記録するようになった
// ときに、それも黙って消える。**allowlist である**(操作を足しても、ここに
// 足さない限り消えない)。
//
// **batch は割れない。** bulk fetch の後続行は、先頭行と同じ時刻・実行者・操作・
// 結果を持つので、先頭行が対象なら後続行も必ず対象になる。
const auditPrunableSQL = `actor_machine_id IS NOT NULL` +
	` AND result = '` + string(ResultSuccess) + `'` +
	` AND action IN ('` + string(ActionSecretRead) + `', '` + string(ActionAuthMachine) + `')`

// 刈り込みが発行する問い合わせ。**どれも表全体を読まない**(索引か、id の範囲で
// 引く)。時刻で全行を引く索引は無い(schema v3 で外した)ので、問い合わせの形を
// 変えると、表を全て読む計画に落ちうる。実行計画はテストで固定している
// (TestPruneAuditLogsNeverScansTheWholeTable)。定数にしてあるのは、テストが
// 本体と同じ文面を検査するためである。
const (
	// cutoff より前の、一番新しい「一覧の行」(単独の行か batch の先頭行)。
	auditPruneNewestSQL = `
		SELECT id FROM audit_logs WHERE batch_id IS NULL AND at < ?
		ORDER BY at DESC, id DESC LIMIT 1`
	// その行を先頭とする batch の、最後の後続行。
	auditPruneBatchEndSQL = `SELECT MAX(id) FROM audit_logs WHERE batch_id = ?`
	// 範囲 (after, upper] の、先頭から N 行目。
	auditPruneNthSQL = `
		SELECT id FROM audit_logs WHERE id > ? AND id <= ?
		ORDER BY id LIMIT 1 OFFSET ?`
	// ある行より後ろの、最初の「一覧の行」。
	auditPruneNextHeadSQL = `
		SELECT id FROM audit_logs WHERE id > ? AND id <= ? AND batch_id IS NULL
		ORDER BY id LIMIT 1`
	// 範囲 (after, end] に、対象の行があるか。
	auditPruneAnySQL = `
		SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id > ? AND id <= ? AND at < ? AND ` + auditPrunableSQL + `)`
	// 範囲 (after, end] の、対象の行を消す。
	auditPruneDeleteSQL = `DELETE FROM audit_logs WHERE id > ? AND id <= ? AND at < ? AND ` + auditPrunableSQL
	// upper までの、対象の行を数える(--dry-run)。
	auditPruneCountSQL = `SELECT COUNT(*) FROM audit_logs WHERE id <= ? AND at < ? AND ` + auditPrunableSQL
)

// cmdAuditPrune は、古い監査行を刈り込む。
//
// **Web UI にも API にも、監査ログを消す口は無い。** あるのはこのコマンドだけ
// である(AGENTS.md ルール 28)。DB ファイルに対して直接実行するので、実行できる
// のは DB ファイルに届く OS ユーザーに限られる。その主体は、もともと DB を直接
// 書き換えられる(THREAT_MODEL N1)。このコマンドは新しい能力を与えない
// (`hokora backup` を監査しない理由と同じ)。
//
// 稼働中のサーバーを止めずに実行できる(SQLite は WAL で複数プロセスの並行
// アクセスを許す)。定期実行は hokora の外(systemd timer 等)で行う。
func cmdAuditPrune(ctx context.Context, args []string) (err error) {
	flags := flag.NewFlagSet("audit-prune", flag.ContinueOnError)
	// エラーの体裁は main に一本化する(cmd_init.go と同じ理由)。
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", DefaultDBPath, "path to the SQLite database file")
	keepDays := flags.Int("keep-days", 0,
		fmt.Sprintf("keep the last N days of prunable audit rows (required; at least %d)", minAuditKeepDays))
	dryRun := flags.Bool("dry-run", false, "only count the rows that would be pruned; change nothing")
	if handled, err := parseFlags(flags, args); handled {
		return err
	}
	// **既定値を持たない。** 値を省いた実行で行が消えることがあってはならない。
	if *keepDays == 0 {
		return errors.New("audit-prune: --keep-days is required")
	}
	if *keepDays < minAuditKeepDays || *keepDays > maxAuditKeepDays {
		return fmt.Errorf("audit-prune: --keep-days must be between %d and %d", minAuditKeepDays, maxAuditKeepDays)
	}
	if err := requireDatabaseOwner(*dbPath, os.Geteuid()); err != nil {
		return fmt.Errorf("audit-prune: %w", err)
	}

	// **止められたら、そこまでに消した行数を記録して終わる。** シグナルを
	// 受けないと、Ctrl-C や systemd の停止でプロセスがそのまま消え、「始めた」
	// 行だけが残る。
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// OpenStore を通す(スキーマの版が合わない DB を弾く。store.go)。
	store, err := OpenStore(ctx, *dbPath)
	if err != nil {
		return fmt.Errorf("audit-prune: %w", err)
	}
	defer closeStore(store, &err)

	cutoff := time.Now().Add(-time.Duration(*keepDays) * 24 * time.Hour)
	before := cutoff.Local().Format("2006-01-02 15:04:05")

	if *dryRun {
		n, err := CountPrunableAuditLogs(ctx, store.DB(), cutoff)
		if err != nil {
			return fmt.Errorf("audit-prune: %w", err)
		}
		fmt.Fprintf(os.Stderr, "dry run: %d audit rows before %s would be pruned\n", n, before)
		return nil
	}

	n, err := PruneAuditLogs(ctx, store.DB(), cutoff, time.Now, auditPruneChunkRows)
	if err != nil {
		return fmt.Errorf("audit-prune: %w (pruned %d rows before the failure)", err, n)
	}
	fmt.Fprintf(os.Stderr, "pruned %d audit rows before %s\n", n, before)
	return nil
}

// requireDatabaseOwner は、uid が DB ファイルの所有者であることを確かめる。
//
// **root で実行させない。** このコマンドは DB を読み書きで開く。所有者以外
// (典型的には `sudo` に `-u hokora` を付け忘れた root)が開くと、SQLite が
// 随伴ファイル(-wal / -shm)をその OS ユーザーの所有で作ることがある。
// それが残ると、サーバーは監査を書けず、secret の読み取りが全て失敗する
// (fail closed)。
func requireDatabaseOwner(path string, uid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat the database: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// 所有者を取れない環境では検査しない(hokora の対象は Linux である)。
		return nil
	}
	if owner := int(stat.Uid); owner != uid {
		return fmt.Errorf("must run as the owner of the database file (uid %d), not uid %d: use `sudo -n -u <owner>`", owner, uid)
	}
	return nil
}

// auditPruneUpperBound は、刈り込みが触ってよい id の上限を返す。対象になり
// うる行が無ければ 0 を返す。
//
// cutoff より前の、一番新しい「一覧の行」を idx_audit_head で引き、それが
// batch の先頭行なら最後の後続行まで含める。id は書いた順に増えるので、
// cutoff より前の行は、ほぼ全てこの上限以下にある。
//
// **上限を先に決めるのは、表全体を読まないためである。** 上限が無いと、「対象の
// 行はもう無い」と分かるまでに、残す期間の行(半年ぶんなら数百万行)を全て読む
// ことになる。
//
// **この上限以下の行は、もう変わらない。** 新しい行は必ずこれより大きい id で
// 書かれ、監査行は書き換えない。以後の問い合わせが見る範囲は、他の書き込みと
// 重ならない(だから、読んでから消す間にロックを持ち続けなくてよい)。
//
// 稀に、時刻は cutoff より前なのに id が上限を超える行がある(時刻は処理の
// 開始時に決まり、id は書き込みの順に決まるため)。それは数にも入らず、次の
// 実行で消える。期間内の行を巻き込まない側に倒してある。
func auditPruneUpperBound(ctx context.Context, db *sql.DB, before int64) (int64, error) {
	var upper int64
	err := db.QueryRowContext(ctx, auditPruneNewestSQL, before).Scan(&upper)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("find the newest audit row before the cutoff: %w", err)
	}

	var tail sql.NullInt64
	if err := db.QueryRowContext(ctx, auditPruneBatchEndSQL, upper).Scan(&tail); err != nil {
		return 0, fmt.Errorf("find the end of the batch: %w", err)
	}
	if tail.Valid && tail.Int64 > upper {
		upper = tail.Int64
	}
	return upper, nil
}

// CountPrunableAuditLogs は、cutoff より前の、刈り込みの対象になる行を数える。
func CountPrunableAuditLogs(ctx context.Context, db *sql.DB, cutoff time.Time) (int64, error) {
	upper, err := auditPruneUpperBound(ctx, db, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	var n int64
	if err := db.QueryRowContext(ctx, auditPruneCountSQL, upper, cutoff.Unix()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count prunable audit logs: %w", err)
	}
	return n, nil
}

// PruneAuditLogs は、cutoff より前の、刈り込みの対象になる行を消し、消した
// 行数を返す。now は現在時刻を返す(テストで固定する)。chunkRows は 1 回に
// 読み進める行数の目安である。
//
// **cutoff は、現在より minAuditKeep 以上前でなければならない。** 下限は
// コマンドの引数の検査だけに置かない。消す関数が自分で守る(AGENTS.md ルール 28)。
//
// **記録してから消す。** 最初に audit.prune の行(どこまでを対象にしたか)を
// 書き、それが書けなければ 1 行も消さない(fail closed。刈り込みは緊急の
// 操作ではない)。終わったら、消した行数を持つ行をもう 1 つ書く。**途中で失敗
// したときや止められたときも、そこまでに消した行数を failure として書く。**
// 終わりの行が無ければ、プロセスごと止まったことが分かる。
//
// 消すのは監査ログの行だけである。**secret、鍵、machine、grant には触れない。**
func PruneAuditLogs(ctx context.Context, db *sql.DB, cutoff time.Time, now func() time.Time, chunkRows int) (total int64, err error) {
	started := now()
	if started.Sub(cutoff) < minAuditKeep {
		return 0, fmt.Errorf("prune audit logs: the cutoff must be at least %d days ago", minAuditKeepDays)
	}

	before := cutoff.Unix()
	// 「始めた」行である。result は「刈り込みを始められた」ことを表し、件数は
	// まだ無い。
	if err := RecordAudit(ctx, db,
		cliAudit(started).entry(ActionAuditPrune, ResultSuccess, &AuditDetail{Before: &before})); err != nil {
		return 0, err
	}
	defer func() {
		result := ResultSuccess
		if err != nil {
			result = ResultFailure
		}
		done := cliAudit(now()).entry(ActionAuditPrune, result, &AuditDetail{Before: &before, Count: &total})
		// ctx が切れて止まったときも、消した行数は残す。
		if rerr := RecordAudit(context.WithoutCancel(ctx), db, done); rerr != nil {
			err = errors.Join(err, rerr)
		}
	}()

	upper, err := auditPruneUpperBound(ctx, db, before)
	if err != nil {
		return 0, err
	}
	for after := int64(0); after < upper; {
		var n int64
		n, after, err = pruneAuditChunk(ctx, db, before, after, upper, chunkRows)
		total += n
		if err != nil {
			return total, err
		}
		// 消したときだけ、次の削除の前に書き込みを譲る。**最後の 1 回の後は
		// 待たない**(全て消し終えた後で止められて、失敗として記録されるのを
		// 避ける)。消すものが無かった回は書き込みロックを取っていない。
		if n == 0 || after >= upper {
			continue
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(auditPruneYield):
		}
	}
	return total, nil
}

// pruneAuditChunk は、id が (after, upper] の範囲を chunkRows 行ほど読み進め、
// その中の対象の行を消す。消した行数と、読み進めた位置(次の after)を返す。
//
// **どの問い合わせも id の範囲で引く。** 読む量は、この回に進む分だけである
// (表の行数にも、残す行の数にも依らない)。
//
// **区切りは、必ず「一覧の行」の直前に置く。** batch の行は id が連続し、先頭行
// (batch_id IS NULL)から始まる。次の先頭行の手前で切れば、batch が 2 回に
// 分かれることは無い。
//
// **消すのは DELETE 文 1 つである。** 1 つの文は全部が成功するか、全部が失敗
// する。だから、途中で止まっても、先頭行だけ、または後続行だけが残ることが無い
// (後続行だけが残ると、監査ログ画面に出なくなる)。明示的なトランザクションは
// 使わない。範囲を決める読み取りは、upper 以下の行がもう変わらないので、
// ロックの外で行える(auditPruneUpperBound)。DELETE は自分で書き込みロックを
// 取ってから読むので、deferred のトランザクションで読んでから書くときの
// SQLITE_BUSY_SNAPSHOT も起きない。
//
// **消すものが無い範囲では、書き込みロックを取らない。** 消えない行(失敗の行は
// 未認証の試行で増やせる)が溜まった古い範囲を通り抜けるとき、行数ぶんの
// ロックの取り直しで、サーバーの書き込みを待たせないためである。
func pruneAuditChunk(ctx context.Context, db *sql.DB, before, after, upper int64, chunkRows int) (_, next int64, err error) {
	// after から chunkRows 行目を見つけ、その先の最初の「一覧の行」の手前までを
	// この回の範囲にする。どちらかが無ければ、upper までが範囲である。
	end := upper
	var nth, head int64
	err = db.QueryRowContext(ctx, auditPruneNthSQL, after, upper, chunkRows-1).Scan(&nth)
	if err == nil {
		err = db.QueryRowContext(ctx, auditPruneNextHeadSQL, nth, upper).Scan(&head)
		if err == nil {
			end = head - 1
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, after, fmt.Errorf("prune audit logs: find the end of the chunk: %w", err)
	}

	var found bool
	if err := db.QueryRowContext(ctx, auditPruneAnySQL, after, end, before).Scan(&found); err != nil {
		return 0, after, fmt.Errorf("prune audit logs: look for prunable rows: %w", err)
	}
	if !found {
		return 0, end, nil
	}

	// **削除の文は、取り消しの対象から外す。** 文が確定した直後に ctx が取り消される
	// と、ドライバは「取り消された」を返す。行は消えているのに、その回の件数が
	// 分からなくなり、記録の件数が実際より少なくなる。1 回ぶんは十数ミリ秒で
	// 終わるので、止める合図は文の手前で受け、文そのものは最後まで走らせる。
	if err := ctx.Err(); err != nil {
		return 0, after, err
	}
	res, err := db.ExecContext(context.WithoutCancel(ctx), auditPruneDeleteSQL, after, end, before)
	if err != nil {
		return 0, after, fmt.Errorf("prune audit logs: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, after, fmt.Errorf("prune audit logs: %w", err)
	}
	return n, end, nil
}
