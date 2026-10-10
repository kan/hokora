package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pruneNow は刈り込みのテストでの「いま」である。行はこれより前の日付で作る。
var pruneNow = vaultNow.Add(400 * 24 * time.Hour)

func pruneClock() time.Time { return pruneNow }

func daysAgo(d int) time.Time { return pruneNow.Add(-time.Duration(d) * 24 * time.Hour) }

// auditSummary は、監査行を「操作/結果@何日前」の形で、古い順に返す。
func auditSummary(t *testing.T, db *sql.DB) []string {
	t.Helper()
	return queryStrings(t, db, fmt.Sprintf(
		`SELECT action || '/' || result || '@' || ((%d - at) / 86400) FROM audit_logs ORDER BY id`, pruneNow.Unix()))
}

// pruneRecords は audit.prune の行を「結果 detail」の形で、古い順に返す。
type pruneRecord struct {
	Result string
	AuditDetail
}

func pruneRecords(t *testing.T, db *sql.DB) []pruneRecord {
	t.Helper()

	var out []pruneRecord
	for _, s := range queryStrings(t, db,
		`SELECT result || ' ' || detail FROM audit_logs WHERE action = 'audit.prune' ORDER BY id`) {
		result, detail, _ := strings.Cut(s, " ")
		r := pruneRecord{Result: result}
		if err := json.Unmarshal([]byte(detail), &r.AuditDetail); err != nil {
			t.Fatalf("decode audit.prune detail %q: %v", detail, err)
		}
		out = append(out, r)
	}
	return out
}

// mustPrune は、直近 30 日を残して刈り込む。
func mustPrune(t *testing.T, db *sql.DB, chunkRows int) int64 {
	t.Helper()

	n, err := PruneAuditLogs(t.Context(), db, daysAgo(30), pruneClock, chunkRows)
	if err != nil {
		t.Fatalf("PruneAuditLogs: %v", err)
	}
	return n
}

func mustRecordBatch(t *testing.T, db *sql.DB, entries []AuditEntry) {
	t.Helper()
	if err := recordBatch(t, db, entries); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
}

// **消えるのは、期間を過ぎた「machine の成功」だけである。** 失敗、人の操作、
// 期間内の行は残る。
func TestPruneAuditLogsRemovesOnlyOldRoutineRows(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t) // machine.create が 1 行入る(vaultNow = 400 日前)
	machine := func(d int) auditCtx { return machineAudit(s.machineID, "10.0.0.2", daysAgo(d)) }
	forbidden, badCreds := ReasonForbidden, ReasonInvalidCredentials

	for _, d := range []int{200, 31, 29} {
		// 消える対象: machine の認証の成功と、読み取りの成功(bulk と単独)。
		mustRecord(t, s.db, machine(d).machineEntry(ActionAuthMachine, s.machineID))
		mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(d), "A", "B", "C"))
		mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(d), "D")...)

		// 残る: 失敗。
		denied := machine(d).entry(ActionSecretRead, ResultFailure, &AuditDetail{Reason: &forbidden})
		denied.TargetMachineID = &s.machineID
		mustRecord(t, s.db, denied)
		mustRecord(t, s.db, auditCtx{Actor: ActorAnonymous, Now: daysAgo(d)}.
			entry(ActionAuthMachine, ResultFailure, &AuditDetail{Reason: &badCreds}))
		// 残る: 人の操作。
		reveal := s.userAudit(daysAgo(d)).entry(ActionSecretReveal, ResultSuccess, nil)
		target := "myapp/prod/A"
		reveal.Target = &target
		mustRecord(t, s.db, reveal, s.userAudit(daysAgo(d)).entry(ActionAuthUser, ResultSuccess, nil))
	}

	if n := mustPrune(t, s.db, 100); n != 10 {
		t.Errorf("pruned %d rows, want 10 (auth + 3 + 1 for each of the two old days)", n)
	}

	want := []string{"machine.create/success@400"}
	for _, d := range []int{200, 31} {
		want = append(want,
			fmt.Sprintf("secret.read/failure@%d", d), fmt.Sprintf("auth.machine/failure@%d", d),
			fmt.Sprintf("secret.reveal/success@%d", d), fmt.Sprintf("auth.user/success@%d", d))
	}
	// 期間内(29 日前)は、対象の操作でも全て残る。
	want = append(want,
		"auth.machine/success@29", "secret.read/success@29", "secret.read/success@29", "secret.read/success@29",
		"secret.read/success@29", "secret.read/failure@29", "auth.machine/failure@29",
		"secret.reveal/success@29", "auth.user/success@29",
		// 刈り込みの記録(始めた / 終えた)。
		"audit.prune/success@0", "audit.prune/success@0")
	if got := auditSummary(t, s.db); !slices.Equal(got, want) {
		t.Errorf("rows after the prune:\n got  %v\n want %v", got, want)
	}
}

// **対象は「machine の」成功である。操作の名前だけでは選ばない。**
//
// いま secret.read を記録するのは Machine API だけだが、条件が操作と結果だけ
// だと、人や admin socket が同じ操作を記録するようになったときに、それも黙って
// 消える。「人の操作は消さない」を、呼び出し側の事情ではなく条件そのもので守る。
func TestPruneAuditLogsKeepsRoutineActionsByNonMachineActors(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	old := daysAgo(100)
	mustRecord(t, s.db,
		s.userAudit(old).entry(ActionSecretRead, ResultSuccess, nil),
		socketAudit(old).entry(ActionSecretRead, ResultSuccess, nil),
		socketAudit(old).entry(ActionAuthMachine, ResultSuccess, nil),
	)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", old, "A")...) // machine の読み取り

	if n := mustPrune(t, s.db, 100); n != 1 {
		t.Errorf("pruned %d rows, want only the machine's read", n)
	}
	want := []string{"user:1", ActorAnonymous, ActorAnonymous}
	want[0] = actorUser(s.userID)
	if got := queryStrings(t, s.db, `SELECT actor FROM audit_logs WHERE action IN ('secret.read', 'auth.machine') ORDER BY id`); !slices.Equal(got, want) {
		t.Errorf("remaining routine-action rows are by %v, want %v", got, want)
	}
}

// **ちょうど境界の行は残る**(cutoff より前だけを消す)。
func TestPruneAuditLogsKeepsRowsAtTheCutoff(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	cutoff := daysAgo(30)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", cutoff.Add(-time.Second), "OLD")...)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", cutoff, "EDGE")...)

	if n := mustPrune(t, s.db, 100); n != 1 {
		t.Errorf("pruned %d rows, want 1", n)
	}
	if got := queryStrings(t, s.db, `SELECT target FROM audit_logs WHERE action = 'secret.read'`); !slices.Equal(got, []string{"myapp/prod/EDGE"}) {
		t.Errorf("remaining reads = %v, want only the row at the cutoff", got)
	}
}

// **下限(30 日)は、消す関数が自分で守る。** コマンドの引数の検査を通らない
// 呼び出し(将来の別の入口、誤った cutoff)でも、直近の記録は消えない。
func TestPruneAuditLogsRefusesARecentCutoff(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(40), "A")...)

	for name, cutoff := range map[string]time.Time{
		"29 days":            daysAgo(29),
		"one second short":   daysAgo(30).Add(time.Second),
		"now":                pruneNow,
		"in the future":      pruneNow.Add(24 * time.Hour),
		"far in the future":  pruneNow.Add(100 * 365 * 24 * time.Hour),
		"zero time is fine?": {},
	} {
		n, err := PruneAuditLogs(t.Context(), s.db, cutoff, pruneClock, 100)
		if name == "zero time is fine?" {
			// 遠い過去の cutoff は下限を満たす(何も消えないだけである)。
			if err != nil || n != 0 {
				t.Errorf("a cutoff in the distant past: n = %d, err = %v; want nothing pruned and no error", n, err)
			}
			continue
		}
		if err == nil || n != 0 {
			t.Errorf("%s: n = %d, err = %v; want a refusal", name, n, err)
		}
	}
	if got := countAuditLogs(t, s.db, ActionSecretRead); got != 1 {
		t.Errorf("%d secret.read rows left, want the old row untouched", got)
	}
	// 拒否した呼び出しは、記録も残さない(何も始めていない)。遠い過去の 1 回だけが残る。
	if got := countAuditLogs(t, s.db, ActionAuditPrune); got != 2 {
		t.Errorf("%d audit.prune rows, want 2 (only the accepted call)", got)
	}
}

// **刈り込みは、何をどこまで消したかを監査に残す。その記録は次の刈り込みでも
// 消えない。**
func TestPruneAuditLogsRecordsItselfAndKeepsTheRecord(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100), "A", "B", "C"))

	// 始めた時刻と終えた時刻は別に記録される。
	times := []time.Time{pruneNow, pruneNow.Add(90 * time.Second)}
	clock := func() time.Time {
		now := times[0]
		if len(times) > 1 {
			times = times[1:]
		}
		return now
	}
	if _, err := PruneAuditLogs(t.Context(), s.db, daysAgo(30), clock, 100); err != nil {
		t.Fatalf("PruneAuditLogs: %v", err)
	}

	recs := pruneRecords(t, s.db)
	if len(recs) != 2 {
		t.Fatalf("%d audit.prune rows, want 2 (started / finished)", len(recs))
	}
	before := daysAgo(30).Unix()
	for i, r := range recs {
		if r.Result != string(ResultSuccess) {
			t.Errorf("record %d: result = %q, want success", i, r.Result)
		}
		if r.Before == nil || *r.Before != before {
			t.Errorf("record %d: before = %v, want %d", i, r.Before, before)
		}
		if r.Via == nil || *r.Via != ViaCLI {
			t.Errorf("record %d: via = %v, want %q", i, r.Via, ViaCLI)
		}
	}
	// 「始めた」行は件数を持たず、「終えた」行が消した件数を持つ。
	if recs[0].Count != nil {
		t.Errorf("the first record already has a count (%d)", *recs[0].Count)
	}
	if recs[1].Count == nil || *recs[1].Count != 3 {
		t.Errorf("the second record count = %v, want 3", recs[1].Count)
	}
	if got := queryStrings(t, s.db, `SELECT actor || ' ' || at FROM audit_logs WHERE action = 'audit.prune' ORDER BY id`); !slices.Equal(got, []string{
		fmt.Sprintf("%s %d", ActorAnonymous, pruneNow.Unix()),
		fmt.Sprintf("%s %d", ActorAnonymous, pruneNow.Unix()+90),
	}) {
		t.Errorf("audit.prune actor and time = %v, want anonymous at the start and at the end", got)
	}

	// 1 年後にもう一度。前回の記録は、期間を過ぎていても残る。
	later := pruneNow.Add(365 * 24 * time.Hour)
	if n, err := PruneAuditLogs(t.Context(), s.db, later.Add(-minAuditKeep), func() time.Time { return later }, 100); err != nil || n != 0 {
		t.Fatalf("second prune: n = %d, err = %v; want nothing left to prune", n, err)
	}
	recs = pruneRecords(t, s.db)
	if len(recs) != 4 {
		t.Fatalf("%d audit.prune rows after the second run, want 4 (the old records must survive)", len(recs))
	}
	if recs[3].Count == nil || *recs[3].Count != 0 {
		t.Errorf("the last record count = %v, want 0", recs[3].Count)
	}
}

// **監査が書けなければ、1 行も消さない**(fail closed)。
func TestPruneAuditLogsFailsClosedWhenTheRecordCannotBeWritten(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100), "A")...)
	if _, err := s.db.ExecContext(t.Context(), `
		CREATE TRIGGER no_prune_record BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'audit.prune'
		BEGIN SELECT RAISE(ABORT, 'audit write failed'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	n, err := PruneAuditLogs(t.Context(), s.db, daysAgo(30), pruneClock, 100)
	if err == nil {
		t.Fatal("PruneAuditLogs succeeded although its own record could not be written")
	}
	if n != 0 || countAuditLogs(t, s.db, ActionSecretRead) != 1 {
		t.Errorf("pruned %d rows without a record; the old read must still be there", n)
	}
}

// **途中で失敗しても、そこまでに消した行数が記録に残る。**
// 消した事実だけがあって、どれだけ消えたかが分からない、という状態を作らない。
func TestPruneAuditLogsRecordsAFailureWithTheCountSoFar(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	for i, key := range []string{"A", "B", "C", "POISON", "E"} {
		mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100-i), key)...)
	}
	// 4 行目の削除だけを失敗させる。1 行ずつ進めるので、3 行は消えている。
	if _, err := s.db.ExecContext(t.Context(), `
		CREATE TRIGGER fail_one_delete BEFORE DELETE ON audit_logs
		WHEN OLD.target = 'myapp/prod/POISON'
		BEGIN SELECT RAISE(ABORT, 'delete failed'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	n, err := PruneAuditLogs(t.Context(), s.db, daysAgo(30), pruneClock, 1)
	if err == nil || n != 3 {
		t.Fatalf("n = %d, err = %v; want a failure after 3 rows", n, err)
	}
	recs := pruneRecords(t, s.db)
	if len(recs) != 2 {
		t.Fatalf("%d audit.prune rows, want 2 (started / failed)", len(recs))
	}
	if recs[1].Result != string(ResultFailure) || recs[1].Count == nil || *recs[1].Count != 3 {
		t.Errorf("the closing record = %s count %v, want failure with count 3", recs[1].Result, recs[1].Count)
	}
	if got := queryStrings(t, s.db, `SELECT target FROM audit_logs WHERE action = 'secret.read' ORDER BY id`); !slices.Equal(got, []string{"myapp/prod/POISON", "myapp/prod/E"}) {
		t.Errorf("remaining reads = %v, want the failed row and everything after it", got)
	}
}

// 始める前に取り消されていたら、何も消さず、記録も残さない(始めていない)。
func TestPruneAuditLogsDoesNothingWhenAlreadyCancelled(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100), "A")...)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if n, err := PruneAuditLogs(ctx, s.db, daysAgo(30), pruneClock, 100); err == nil || n != 0 {
		t.Fatalf("n = %d, err = %v; want an error and nothing pruned", n, err)
	}
	if got := countAuditLogs(t, s.db, ActionSecretRead); got != 1 {
		t.Errorf("%d secret.read rows left, want the old row untouched", got)
	}
	if got := countAuditLogs(t, s.db, ActionAuditPrune); got != 0 {
		t.Errorf("%d audit.prune rows, want none", got)
	}
}

// **batch は割れない。** 1 回に読み進める行数の切れ目が batch の途中に来ても、
// 先頭行だけ、または後続行だけが残る状態を、途中のどの時点でも作らない
// (プロセスが 2 つのトランザクションの間で止まっても、表示が壊れない)。
func TestPruneAuditLogsNeverSplitsABatch(t *testing.T) {
	t.Parallel()

	for _, chunk := range []int{1, 2, 3, 4, 5, 7, 100} {
		t.Run(fmt.Sprintf("chunk of %d", chunk), func(t *testing.T) {
			t.Parallel()

			s := newAuditSeed(t)
			// 大きさの違う batch と単独の行、消えない行を、古い順に並べる。
			for i, keys := range [][]string{{"A", "B", "C", "D", "E"}, {"F"}, {"G", "H"}, {"I", "J", "K"}} {
				at := daysAgo(100 - i)
				mustRecord(t, s.db, machineAudit(s.machineID, "10.0.0.2", at).machineEntry(ActionAuthMachine, s.machineID))
				mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", at, keys...))
				mustRecord(t, s.db, s.userAudit(at).entry(ActionAuthUser, ResultSuccess, nil))
			}
			// 期間内の batch。最後まで残る。
			mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(1), "X", "Y"))

			_, sizes := splitBatches(auditBatchRows(t, s.db, ActionSecretRead))
			before := daysAgo(30).Unix()
			upper, err := auditPruneUpperBound(t.Context(), s.db, before)
			if err != nil {
				t.Fatalf("auditPruneUpperBound: %v", err)
			}

			// 1 回ぶんずつ進めて、毎回「先頭行の無い後続行」と「後続行の欠けた
			// batch」が無いことを確かめる。
			var total int64
			steps := 0
			for after := int64(0); after < upper; steps++ {
				var n int64
				prev := after
				n, after, err = pruneAuditChunk(t.Context(), s.db, before, after, upper, chunk)
				if err != nil {
					t.Fatalf("pruneAuditChunk: %v", err)
				}
				if after <= prev || steps > 100 {
					t.Fatalf("step %d: pruneAuditChunk does not make progress (after %d -> %d)", steps, prev, after)
				}
				total += n

				heads, members := splitBatches(auditBatchRows(t, s.db, ActionSecretRead))
				for head, rows := range members {
					if !slices.Contains(heads, head) {
						t.Fatalf("step %d: rows %v point at the deleted head %d", steps, rows, head)
					}
					if len(rows) != len(sizes[head]) {
						t.Fatalf("step %d: batch %d has %d of its %d later rows", steps, head, len(rows), len(sizes[head]))
					}
				}
			}
			// auth 4 行 + 読み取り 11 行。
			if total != 15 {
				t.Errorf("pruned %d rows in total, want 15", total)
			}
			if got := countAuditLogs(t, s.db, ActionSecretRead); got != 2 {
				t.Errorf("%d secret.read rows left, want the recent batch of 2", got)
			}
			if got := countAuditLogs(t, s.db, ActionAuthUser); got != 4 {
				t.Errorf("%d auth.user rows left, want all 4", got)
			}
		})
	}
}

// **刈り込みは、表全体を読まない。**
//
// 時刻で全行を引く索引は無い(schema v3)。上限を決めずに「対象の行はもう無い」と
// 確かめようとすると、残す期間の行を全て読む。それを書き込みロックの中で行うと、
// その間 secret の読み取りが待たされる(実測: 446 万行で約 0.5 秒が 2 回)。
// 行数を増やして時間を測るのではなく、実行計画で固定する。
func TestPruneAuditLogsNeverScansTheWholeTable(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	// **本体が発行する文面そのもの**(定数)の計画を見る。写しを検査すると、
	// 本体の問い合わせを変えたときに、古い写しのまま通ってしまう。
	plans := map[string]string{
		"upper bound":            queryPlan(t, db, auditPruneNewestSQL, 1),
		"end of the upper batch": queryPlan(t, db, auditPruneBatchEndSQL, 1),
		"nth row of the chunk":   queryPlan(t, db, auditPruneNthSQL, 1, 2, 3),
		"next head":              queryPlan(t, db, auditPruneNextHeadSQL, 1, 2),
		"anything to prune":      queryPlan(t, db, auditPruneAnySQL, 1, 2, 3),
		"delete":                 queryPlan(t, db, auditPruneDeleteSQL, 1, 2, 3),
		"count (dry run)":        queryPlan(t, db, auditPruneCountSQL, 1, 2),
	}
	for name, plan := range plans {
		if strings.Contains(plan, "SCAN audit_logs") || strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("%s: the plan reads or sorts the whole table: %s", name, plan)
		}
		if !strings.Contains(plan, "SEARCH audit_logs") {
			t.Errorf("%s: the plan does not seek into audit_logs: %s", name, plan)
		}
	}
	if p := plans["upper bound"]; !strings.Contains(p, "idx_audit_head") {
		t.Errorf("upper bound: the plan does not use idx_audit_head: %s", p)
	}
}

// 時刻は cutoff より前なのに、id が新しい行より後ろにある行(時刻は処理の開始時に
// 決まり、id は書き込みの順に決まる)。**その回で消えなくても、期間内の行を
// 巻き込まない。** 次の実行で消える。
func TestPruneAuditLogsLeavesOutOfOrderRowsForTheNextRun(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100), "OLD")...)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(1), "RECENT")...)
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(90), "LATE")...) // 古い時刻だが、後から書かれた

	mustPrune(t, s.db, 100)
	got := queryStrings(t, s.db, `SELECT target FROM audit_logs WHERE action = 'secret.read' ORDER BY id`)
	if !slices.Contains(got, "myapp/prod/RECENT") || slices.Contains(got, "myapp/prod/OLD") {
		t.Fatalf("reads after the prune = %v; the recent row must stay and the old row must go", got)
	}

	// 期間内の行が全て期間を過ぎた後の実行で、残りも消える。
	later := pruneNow.Add(60 * 24 * time.Hour)
	if _, err := PruneAuditLogs(t.Context(), s.db, later.Add(-minAuditKeep), func() time.Time { return later }, 100); err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if n := countAuditLogs(t, s.db, ActionSecretRead); n != 0 {
		t.Errorf("%d secret.read rows left after the second run, want 0", n)
	}
}

// **稼働中のサーバーが書き続けていても、刈り込みは通り、書き込みも失敗しない。**
//
// 刈り込みは読んでから消す。書き込みロックを先に取らないと、合間に入った
// 書き込みで SQLITE_BUSY_SNAPSHOT になる。逆に刈り込みがロックを持ち続けると、
// secret の読み取り(監査の INSERT が要る)が待ちきれずに失敗する。
// race detector では見えないので、結果で確かめる(ルール 68)。
func TestPruneAuditLogsWhileTheServerKeepsWriting(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	const oldBatches = 300
	for i := range oldBatches {
		mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100).Add(time.Duration(i)*time.Second), "A", "B", "C", "D"))
	}

	const (
		writers = 4
		rounds  = 40
	)
	var wg sync.WaitGroup
	errs := make(chan error, writers*rounds+1)
	for w := range writers {
		wg.Go(func() {
			for i := range rounds {
				at := daysAgo(1).Add(time.Duration(w*rounds+i) * time.Second)
				errs <- recordBatch(t, s.db, s.readEntries(s.prodID, "prod", at, "A", "B", "C"))
			}
		})
	}
	var pruned int64
	wg.Go(func() {
		n, err := PruneAuditLogs(t.Context(), s.db, daysAgo(30), pruneClock, 50)
		pruned = n
		errs <- err
	})
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write or prune: %v", err)
		}
	}

	if pruned != oldBatches*4 {
		t.Errorf("pruned %d rows, want %d", pruned, oldBatches*4)
	}
	// 期間内に書かれた行は、1 行も巻き添えにならない。
	if got := countAuditLogs(t, s.db, ActionSecretRead); got != writers*rounds*3 {
		t.Errorf("%d secret.read rows left, want %d", got, writers*rounds*3)
	}
}

// 刈り込んだ後も、監査ログ画面の一覧は引ける(残った batch は中身が揃っている)。
func TestListAuditLogsAfterAPrune(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100), "A", "B"))
	mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(5), "C", "D", "E"))
	mustPrune(t, s.db, 1)

	rows := mustList(t, s.db, AuditQuery{Filter: AuditFilter{Action: ActionSecretRead}}).Rows
	if len(rows) != 1 || rows[0].BatchSize != 3 || len(rows[0].Batch) != 3 {
		t.Errorf("reads after the prune = %+v, want the recent batch of 3", rows)
	}
	// 刈り込みの記録は一覧に出て、操作で絞り込める。
	prunes := mustList(t, s.db, AuditQuery{Filter: AuditFilter{Action: ActionAuditPrune}}).Rows
	if len(prunes) != 2 || !strings.Contains(prunes[0].Detail, `"count":2`) {
		t.Errorf("audit.prune rows = %+v, want two rows, the newest with the count", prunes)
	}
}

// 数えるだけの問い合わせは、実際に消える行数と一致する。
func TestCountPrunableAuditLogsMatchesThePrune(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	for _, d := range []int{200, 60, 31, 29, 1} {
		mustRecord(t, s.db, machineAudit(s.machineID, "10.0.0.2", daysAgo(d)).machineEntry(ActionAuthMachine, s.machineID))
		mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(d), "A", "B", "C"))
		mustRecord(t, s.db, s.userAudit(daysAgo(d)).entry(ActionAuthUser, ResultSuccess, nil))
	}

	counted, err := CountPrunableAuditLogs(t.Context(), s.db, daysAgo(30))
	if err != nil {
		t.Fatalf("CountPrunableAuditLogs: %v", err)
	}
	if pruned := mustPrune(t, s.db, 3); counted != pruned || pruned != 12 {
		t.Errorf("counted %d, pruned %d; want both to be 12", counted, pruned)
	}
	// 何も無い DB でも数えられる。
	if n, err := CountPrunableAuditLogs(t.Context(), newTestStore(t).DB(), daysAgo(30)); err != nil || n != 0 {
		t.Errorf("empty database: n = %d, err = %v", n, err)
	}
}

// ---- コマンド ----

func TestCmdAuditPruneFlags(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	if err := cmdInit(t.Context(), []string{"-db", path}); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	// **--keep-days は必須で、下限がある。** 省いた実行や打ち間違いで、直近の
	// 記録まで消えてはならない。
	for name, args := range map[string][]string{
		"no keep-days":      {"-db", path},
		"zero":              {"-db", path, "-keep-days", "0"},
		"below the minimum": {"-db", path, "-keep-days", "29"},
		// 日数を期間に直すときに桁あふれする値。213540 日は約 36 日に化ける
		// (そのまま通すと、「全部残す」つもりの指定で直近以外が消える)。
		"wraps to 36 days":   {"-db", path, "-keep-days", "213540"},
		"wraps negative":     {"-db", path, "-keep-days", "106752"},
		"above the maximum":  {"-db", path, "-keep-days", "36501"},
		"negative":           {"-db", path, "-keep-days", "-180"},
		"not a number":       {"-db", path, "-keep-days", "180d"},
		"extra argument":     {"-db", path, "-keep-days", "180", "now"},
		"unknown flag":       {"-db", path, "-keep-days", "180", "-all"},
		"missing database":   {"-db", filepath.Join(t.TempDir(), "typo.db"), "-keep-days", "180"},
		"dry-run needs days": {"-db", path, "-dry-run"},
	} {
		if err := cmdAuditPrune(t.Context(), args); err == nil {
			t.Errorf("%s: cmdAuditPrune%v succeeded", name, args)
		}
	}
	if err := cmdAuditPrune(t.Context(), []string{"-h"}); err != nil {
		t.Errorf("cmdAuditPrune -h = %v, want nil", err)
	}

	// 失敗した実行は、どれも記録を残していない(何も始めていない)。
	store, err := OpenStore(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()
	if n := countAuditLogs(t, store.DB(), ActionAuditPrune); n != 0 {
		t.Errorf("%d audit.prune rows after rejected invocations, want 0", n)
	}
}

// **DB ファイルの所有者以外には実行させない**(`sudo` に `-u hokora` を付け
// 忘れた root が、root 所有の -wal / -shm を作るのを防ぐ)。
func TestRequireDatabaseOwner(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}

	if err := requireDatabaseOwner(path, os.Geteuid()); err != nil {
		t.Errorf("the owner was refused: %v", err)
	}
	// このテストを走らせている uid とは別の uid(root として走っていても別になる値)。
	err := requireDatabaseOwner(path, os.Geteuid()+1)
	if err == nil {
		t.Fatal("a different uid was accepted")
	}
	if !strings.Contains(err.Error(), "owner of the database file") {
		t.Errorf("error = %q, want it to say who must run the command", err)
	}
	if err := requireDatabaseOwner(filepath.Join(t.TempDir(), "missing.db"), os.Geteuid()); err == nil {
		t.Error("a missing file was accepted")
	}
}

// 上限の日数ちょうどは通る(何も消えないだけである)。
func TestCmdAuditPruneAcceptsTheMaximum(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	if err := cmdInit(t.Context(), []string{"-db", path}); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	if err := cmdAuditPrune(t.Context(), []string{"-db", path, "-keep-days", "36500"}); err != nil {
		t.Errorf("cmdAuditPrune --keep-days 36500: %v", err)
	}
}

// **消すものが無い範囲では、DELETE を発行しない**(書き込みロックを取らない)。
//
// 消えない行(失敗の行は未認証の試行で増やせる)が溜まった古い範囲を通り抜ける
// とき、その行数ぶんのロックの取り直しで、サーバーの書き込みを待たせない。
// 別の接続が書き込みロックを持ったままでも通り抜けられることで確かめる。
func TestPruneAuditChunkTakesNoWriteLockWhenNothingIsPrunable(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	reason := ReasonInvalidCredentials
	for i := range 20 {
		mustRecord(t, s.db, auditCtx{Actor: ActorAnonymous, Now: daysAgo(100 - i)}.
			entry(ActionAuthMachine, ResultFailure, &AuditDetail{Reason: &reason}))
	}
	before := daysAgo(30).Unix()
	upper, err := auditPruneUpperBound(t.Context(), s.db, before)
	if err != nil || upper == 0 {
		t.Fatalf("auditPruneUpperBound = %d, %v", upper, err)
	}

	// 別の接続が書き込みロックを持ち続ける(稼働中のサーバーの書き込みに相当)。
	holder, err := s.db.Conn(t.Context())
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(t.Context(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}
	defer func() {
		if _, err := holder.ExecContext(context.WithoutCancel(t.Context()), `ROLLBACK`); err != nil {
			t.Errorf("ROLLBACK: %v", err)
		}
	}()

	// busy_timeout(5 秒)を待たずに通り抜ける。書き込みロックを取りに行けば、
	// ここで 5 秒待ってから失敗する。
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for after := int64(0); after < upper; {
		var n int64
		n, after, err = pruneAuditChunk(ctx, s.db, before, after, upper, 5)
		if err != nil {
			t.Fatalf("pruneAuditChunk waited for the write lock although nothing is prunable: %v", err)
		}
		if n != 0 {
			t.Fatalf("pruned %d rows, want none", n)
		}
	}
}

// 存在しない DB を指しても、新しく作らない(OpenStore は作らない)。
func TestCmdAuditPruneDoesNotCreateADatabase(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "typo", "hokora.db")
	if err := cmdAuditPrune(t.Context(), []string{"-db", path, "-keep-days", "180"}); err == nil {
		t.Fatal("cmdAuditPrune succeeded on a missing database")
	}
	if got, err := filepath.Glob(filepath.Join(filepath.Dir(path), "*")); err != nil || len(got) != 0 {
		t.Errorf("cmdAuditPrune left files behind: %v (err %v)", got, err)
	}
}

// **--dry-run は数えるだけで、何も変えない**(記録も残さない)。
// 実行すると、下限(30 日)ちょうどでも通り、期間を過ぎた行が消える。
func TestCmdAuditPruneDryRunThenRun(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	if err := cmdInit(t.Context(), []string{"-db", path}); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	store, err := OpenStore(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()
	db := store.DB()

	// コマンドは実時刻を使うので、行も実時刻から作る。
	old := machineAudit(1, "10.0.0.2", time.Now().Add(-31*24*time.Hour))
	recent := machineAudit(1, "10.0.0.2", time.Now().Add(-29*24*time.Hour))
	mustRecord(t, db, old.machineEntry(ActionAuthMachine, 1), recent.machineEntry(ActionAuthMachine, 1))
	snapshot := func() []string {
		return queryStrings(t, db, `SELECT id || ':' || action || ':' || at FROM audit_logs ORDER BY id`)
	}
	before := snapshot()

	if err := cmdAuditPrune(t.Context(), []string{"-db", path, "-keep-days", "30", "-dry-run"}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if after := snapshot(); !slices.Equal(before, after) {
		t.Errorf("the dry run changed the audit log:\nbefore %v\nafter  %v", before, after)
	}

	if err := cmdAuditPrune(t.Context(), []string{"-db", path, "-keep-days", "30"}); err != nil {
		t.Fatalf("cmdAuditPrune: %v", err)
	}
	if n := countAuditLogs(t, db, ActionAuthMachine); n != 1 {
		t.Errorf("%d auth.machine rows left, want only the one inside the last 30 days", n)
	}
	if n := countAuditLogs(t, db, ActionAuditPrune); n != 2 {
		t.Errorf("%d audit.prune rows, want 2", n)
	}
}

// ---- 行の並び方、止められたとき、API からの一巡 ----
//
// ここから下は、実装した本人とは別の目で足したテストである(AGENTS.md
// 「コミット前に必ず実行すること」手順 3)。

// pruneRow は、刈り込みの対象かどうかを決める列だけを持つ監査行である。
type pruneRow struct {
	ID      int64
	At      int64
	Batch   sql.NullInt64
	Machine sql.NullInt64
	Action  string
	Result  string
}

// prunable は、行が刈り込みの対象かを判定する。
//
// **本体の条件(auditPrunableSQL)も定数も使わない。** 文字列を直に書いてある
// のは、本体の条件を書き換えたときに、検査の側まで一緒に変わらないようにする
// ためである。
func (r pruneRow) prunable(cutoff int64) bool {
	return r.At < cutoff && r.Machine.Valid && r.Result == "success" &&
		(r.Action == "secret.read" || r.Action == "auth.machine")
}

func pruneRows(t *testing.T, db *sql.DB) []pruneRow {
	t.Helper()

	rows, err := db.QueryContext(t.Context(),
		`SELECT id, at, batch_id, actor_machine_id, action, result FROM audit_logs ORDER BY id`)
	if err != nil {
		t.Fatalf("list audit rows: %v", err)
	}
	defer rows.Close()

	var out []pruneRow
	for rows.Next() {
		var r pruneRow
		if err := rows.Scan(&r.ID, &r.At, &r.Batch, &r.Machine, &r.Action, &r.Result); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// referenceSurvivors は、刈り込みの後に残るはずの id と、消えるはずの行数を、
// DESIGN §10.4 の規則から計算する(本体の問い合わせを使わない)。
//
// 規則: cutoff より前の、一番新しい「一覧の行」(batch_id の無い行)を求め、
// それが batch の先頭行なら最後の後続行までを上限にする。上限以下の id で、
// cutoff より前の「machine の成功」(secret.read / auth.machine)が消える。
func referenceSurvivors(rows []pruneRow, cutoff int64) (survivors []int64, deleted int64) {
	var upper int64
	newest := pruneRow{At: -1 << 62}
	for _, r := range rows {
		if r.Batch.Valid || r.At >= cutoff {
			continue
		}
		if r.At > newest.At || (r.At == newest.At && r.ID > newest.ID) {
			newest = r
			upper = r.ID
		}
	}
	for _, r := range rows {
		if r.Batch.Valid && r.Batch.Int64 == newest.ID && r.ID > upper {
			upper = r.ID
		}
	}
	for _, r := range rows {
		if r.ID <= upper && r.prunable(cutoff) {
			deleted++
			continue
		}
		survivors = append(survivors, r.ID)
	}
	return survivors, deleted
}

// batchSizes は、batch の先頭行の id ごとの、後続行の数を返す。
func batchSizes(t *testing.T, db *sql.DB) map[int64]int {
	t.Helper()

	_, members := splitBatches(auditBatchRows(t, db, ""))
	sizes := make(map[int64]int, len(members))
	for head, rows := range members {
		sizes[head] = len(rows)
	}
	return sizes
}

// assertBatchesIntact は、残っている batch がどれも欠けていないことを確かめる
// (先頭行の無い後続行も、後続行の欠けた batch も無い)。
func assertBatchesIntact(t *testing.T, db *sql.DB, sizes map[int64]int, when string) {
	t.Helper()

	heads, members := splitBatches(auditBatchRows(t, db, ""))
	for head, rows := range members {
		if !slices.Contains(heads, head) {
			t.Fatalf("%s: rows %v point at the missing head %d", when, rows, head)
		}
		if len(rows) != sizes[head] {
			t.Fatalf("%s: batch %d has %d of its %d later rows", when, head, len(rows), sizes[head])
		}
	}
}

// pruneStepwise は、直近 30 日を残して 1 回ぶんずつ刈り込み、毎回 batch が
// 欠けていないことを確かめる。消した行数を返す。
func pruneStepwise(t *testing.T, db *sql.DB, chunk int) int64 {
	t.Helper()

	sizes := batchSizes(t, db)
	before := daysAgo(30).Unix()
	upper, err := auditPruneUpperBound(t.Context(), db, before)
	if err != nil {
		t.Fatalf("auditPruneUpperBound: %v", err)
	}

	var total int64
	steps := 0
	for after := int64(0); after < upper; steps++ {
		var n int64
		prev := after
		n, after, err = pruneAuditChunk(t.Context(), db, before, after, upper, chunk)
		if err != nil {
			t.Fatalf("pruneAuditChunk: %v", err)
		}
		if after <= prev || after > upper || steps > 10000 {
			t.Fatalf("step %d: pruneAuditChunk moved from %d to %d (upper bound %d)", steps, prev, after, upper)
		}
		total += n
		assertBatchesIntact(t, db, sizes, fmt.Sprintf("step %d", steps))
	}
	return total
}

func layoutKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("K%d", i)
	}
	return keys
}

// seedRandomAuditLayout は、種から決まる並びで監査行を作る。
//
// 大きさの違う batch、単独の行、batch_id を持たない古い形の bulk(v2 より前)、
// 消えない行(失敗、人の操作、過去の刈り込みの記録)を混ぜ、いくつかの行を後から
// 消して id に隙間を作る。**種が奇数のときは、時刻の順と id の順を崩す**
// (cutoff をまたいで前後する行ができる)。偶数のときは時刻が id の順に並ぶ。
func seedRandomAuditLayout(t *testing.T, s auditSeed, seed uint64) (monotonic bool) {
	t.Helper()

	//nolint:gosec // G404: テストデータの並びを決めるだけで、秘密は作らない。再現できるよう種を固定する。
	rng := rand.New(rand.NewPCG(seed, 0x686f6b6f7261))
	monotonic = seed%2 == 0
	events := 40 + rng.IntN(30)
	step := 198 * 24 * time.Hour / time.Duration(events)
	forbidden := ReasonForbidden

	type span struct{ from, to int64 }
	var gaps []span
	ctx := t.Context()
	err := withTx(ctx, s.db, func(tx *sql.Tx) error {
		maxID := func() (id int64, err error) {
			err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM audit_logs`).Scan(&id)
			return id, err
		}
		for i := range events {
			at := daysAgo(200).Add(time.Duration(i) * step)
			if !monotonic && rng.IntN(5) == 0 {
				at = at.Add(time.Duration(rng.IntN(81)-40) * 24 * time.Hour)
				if !at.Before(pruneNow) {
					at = pruneNow.Add(-time.Hour)
				}
			}
			machine := machineAudit(s.machineID, "10.0.0.2", at)

			from, err := maxID()
			if err != nil {
				return err
			}
			var entries []AuditEntry
			batch := false
			switch kind := rng.IntN(10); {
			case kind < 4: // bulk fetch(1 件だけの batch も含む)
				entries, batch = s.readEntries(s.prodID, "prod", at, layoutKeys(1+rng.IntN(9))...), true
			case kind == 4:
				entries = []AuditEntry{machine.machineEntry(ActionAuthMachine, s.machineID)}
			case kind == 5: // 単一取得
				entries = s.readEntries(s.prodID, "prod", at, "SINGLE")
			case kind == 6: // v2 より前の bulk。同じ時刻で、batch_id を持たない
				entries = s.readEntries(s.stagingID, "staging", at, layoutKeys(2+rng.IntN(5))...)
			case kind == 7:
				denied := machine.entry(ActionSecretRead, ResultFailure, &AuditDetail{Reason: &forbidden})
				denied.TargetMachineID = &s.machineID
				entries = []AuditEntry{denied}
			case kind == 8:
				entries = []AuditEntry{s.userAudit(at).entry(ActionAuthUser, ResultSuccess, nil)}
			default:
				before := at.Unix()
				entries = []AuditEntry{cliAudit(at).entry(ActionAuditPrune, ResultSuccess, &AuditDetail{Before: &before})}
			}
			if batch {
				err = RecordAuditBatch(ctx, tx, entries)
			} else {
				for _, e := range entries {
					if err = RecordAudit(ctx, tx, e); err != nil {
						break
					}
				}
			}
			if err != nil {
				return err
			}

			to, err := maxID()
			if err != nil {
				return err
			}
			if rng.IntN(7) == 0 {
				gaps = append(gaps, span{from, to})
			}
		}
		// 出来事ごとに丸ごと消すので、batch は欠けない(前回の刈り込みの跡に相当)。
		for _, g := range gaps {
			if _, err := tx.ExecContext(ctx, `DELETE FROM audit_logs WHERE id > ? AND id <= ?`, g.from, g.to); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed %d: build the layout: %v", seed, err)
	}
	return monotonic
}

// **1 回に読み進める行数をどう選んでも、残る行は規則どおりで、同じである。**
//
// 手で並べた形だけでは、区切りの計算が取りこぼす並びを見落とす。種を固定した
// 乱数で並びを作り、本体の問い合わせを使わない計算(referenceSurvivors)と
// 突き合わせる。数えるだけの問い合わせ(--dry-run)も、同じ数を返す。
func TestPruneAuditLogsMatchesTheRuleOnRandomLayouts(t *testing.T) {
	t.Parallel()

	for _, seed := range []uint64{1, 2, 3, 4, 5, 6, 7, 8} {
		for _, chunk := range []int{1, 2, 3, 5, 8, 50} {
			t.Run(fmt.Sprintf("seed %d chunk %d", seed, chunk), func(t *testing.T) {
				t.Parallel()

				s := newAuditSeed(t)
				monotonic := seedRandomAuditLayout(t, s, seed)
				cutoff := daysAgo(30).Unix()
				rows := pruneRows(t, s.db)
				want, wantDeleted := referenceSurvivors(rows, cutoff)
				if wantDeleted == 0 || len(want) < 5 {
					t.Fatalf("seed %d: the layout is degenerate (%d rows, %d to delete); the test checks nothing",
						seed, len(rows), wantDeleted)
				}

				counted, err := CountPrunableAuditLogs(t.Context(), s.db, daysAgo(30))
				if err != nil {
					t.Fatalf("CountPrunableAuditLogs: %v", err)
				}
				total := pruneStepwise(t, s.db, chunk)

				if counted != wantDeleted || total != wantDeleted {
					t.Errorf("seed %d chunk %d: dry run counted %d, pruned %d; the rule says %d",
						seed, chunk, counted, total, wantDeleted)
				}
				var got []int64
				for _, r := range pruneRows(t, s.db) {
					got = append(got, r.ID)
					// 時刻が id の順に並んでいれば、取り残しは 1 行も無い。
					if monotonic && r.prunable(cutoff) {
						t.Errorf("seed %d chunk %d: row %d (%s at %d) is prunable but was left behind",
							seed, chunk, r.ID, r.Action, r.At)
					}
				}
				if !slices.Equal(got, want) {
					t.Errorf("seed %d chunk %d: surviving ids differ from the rule:\n got  %v\n want %v", seed, chunk, got, want)
				}
			})
		}
	}
}

// 区切りの計算が取りこぼしやすい並びを、名前を付けて固定する。
// どれも、1 回に読み進める行数によらず同じ結果になる。
func TestPruneAuditLogsOnAwkwardLayouts(t *testing.T) {
	t.Parallel()

	reads := func(s auditSeed, d int, n int) []AuditEntry {
		return s.readEntries(s.prodID, "prod", daysAgo(d), layoutKeys(n)...)
	}
	auth := func(s auditSeed, d int) AuditEntry {
		return machineAudit(s.machineID, "10.0.0.2", daysAgo(d)).machineEntry(ActionAuthMachine, s.machineID)
	}
	human := func(s auditSeed, d int) AuditEntry {
		return s.userAudit(daysAgo(d)).entry(ActionAuthUser, ResultSuccess, nil)
	}
	failure := func(d int) AuditEntry {
		reason := ReasonInvalidCredentials
		return auditCtx{Actor: ActorAnonymous, Now: daysAgo(d)}.
			entry(ActionAuthMachine, ResultFailure, &AuditDetail{Reason: &reason})
	}
	const (
		seedRow   = "machine.create/success@400" // newAuditSeed が入れる行
		recent    = "secret.read/success@1"
		humanAt   = "auth.user/success@"
		failureAt = "auth.machine/failure@"
	)

	tests := []struct {
		name  string
		build func(t *testing.T, s auditSeed)
		// 刈り込みの記録を除いた、残るはずの行(古い順)。
		want       []string
		wantPruned int64
	}{
		{
			// 上限の行そのものが batch の先頭行で、その後続行が表の最後の行である。
			name: "the table ends with an old batch",
			build: func(t *testing.T, s auditSeed) {
				mustRecord(t, s.db, auth(s, 100))
				mustRecordBatch(t, s.db, reads(s, 100, 5))
			},
			want:       []string{seedRow},
			wantPruned: 6,
		},
		{
			name: "an old batch right below recent rows",
			build: func(t *testing.T, s auditSeed) {
				mustRecordBatch(t, s.db, reads(s, 100, 3))
				mustRecordBatch(t, s.db, reads(s, 31, 7))
				mustRecordBatch(t, s.db, reads(s, 1, 2))
			},
			want:       []string{seedRow, recent, recent},
			wantPruned: 10,
		},
		{
			// cutoff より前の一番新しい「一覧の行」が、消えない行である。
			name: "the newest old row is a kept row",
			build: func(t *testing.T, s auditSeed) {
				mustRecordBatch(t, s.db, reads(s, 100, 4))
				mustRecord(t, s.db, reads(s, 90, 1)...)
				mustRecord(t, s.db, human(s, 50))
				mustRecordBatch(t, s.db, reads(s, 1, 2))
			},
			want:       []string{seedRow, humanAt + "50", recent, recent},
			wantPruned: 5,
		},
		{
			name: "only kept rows are old",
			build: func(t *testing.T, s auditSeed) {
				for d := 120; d > 100; d-- {
					mustRecord(t, s.db, failure(d))
				}
				mustRecord(t, s.db, human(s, 99))
				mustRecordBatch(t, s.db, reads(s, 1, 2))
			},
			want: append(append([]string{seedRow},
				func() (out []string) {
					for d := 120; d > 100; d-- {
						out = append(out, fmt.Sprintf("%s%d", failureAt, d))
					}
					return out
				}()...), humanAt+"99", recent, recent),
			wantPruned: 0,
		},
		{
			// v2 より前の bulk fetch: 同じ時刻の行が並ぶが、batch_id を持たない
			// (どの行も「一覧の行」である)。
			name: "bulk reads written before batch_id existed",
			build: func(t *testing.T, s auditSeed) {
				mustRecord(t, s.db, auth(s, 100))
				mustRecord(t, s.db, reads(s, 100, 6)...)
				mustRecord(t, s.db, human(s, 100))
				mustRecord(t, s.db, reads(s, 100, 4)...)
				mustRecord(t, s.db, reads(s, 1, 2)...)
			},
			want:       []string{seedRow, humanAt + "100", recent, recent},
			wantPruned: 11,
		},
		{
			// 同じ時刻の batch の間に、消えない行が挟まっている。
			name: "kept rows between batches of the same second",
			build: func(t *testing.T, s auditSeed) {
				mustRecordBatch(t, s.db, reads(s, 100, 4))
				mustRecord(t, s.db, human(s, 100))
				mustRecordBatch(t, s.db, reads(s, 100, 4))
				mustRecord(t, s.db, failure(100))
				mustRecordBatch(t, s.db, reads(s, 100, 2))
				mustRecord(t, s.db, human(s, 100))
			},
			want:       []string{seedRow, humanAt + "100", failureAt + "100", humanAt + "100"},
			wantPruned: 10,
		},
		{
			// 上限より下に、期間内の batch がある(時刻は古いが後から書かれた行が
			// 上限を押し上げる)。期間内の batch は丸ごと残る。
			name: "a recent batch below the upper bound",
			build: func(t *testing.T, s auditSeed) {
				mustRecord(t, s.db, reads(s, 100, 1)...)
				mustRecordBatch(t, s.db, reads(s, 1, 3))
				mustRecordBatch(t, s.db, reads(s, 90, 3))
			},
			want:       []string{seedRow, recent, recent, recent},
			wantPruned: 4,
		},
		{
			// id に隙間がある(前回の刈り込みの跡)。
			name: "gaps in the ids",
			build: func(t *testing.T, s auditSeed) {
				for d := 120; d > 108; d-- {
					mustRecordBatch(t, s.db, reads(s, d, 3))
					mustRecord(t, s.db, human(s, d))
				}
				if _, err := s.db.ExecContext(t.Context(),
					`DELETE FROM audit_logs WHERE action = 'secret.read' AND at < ? AND at >= ?`,
					daysAgo(110).Unix(), daysAgo(118).Unix()); err != nil {
					t.Fatalf("make gaps: %v", err)
				}
			},
			want: append([]string{seedRow}, func() (out []string) {
				for d := 120; d > 108; d-- {
					out = append(out, fmt.Sprintf("%s%d", humanAt, d))
				}
				return out
			}()...),
			wantPruned: 12, // 12 個の batch のうち 8 個は先に消してある。残り 4 個 × 3 行
		},
	}
	for _, tt := range tests {
		for _, chunk := range []int{1, 2, 3, 4, 50} {
			t.Run(fmt.Sprintf("%s/chunk of %d", tt.name, chunk), func(t *testing.T) {
				t.Parallel()

				s := newAuditSeed(t)
				tt.build(t, s)
				sizes := batchSizes(t, s.db)

				counted, err := CountPrunableAuditLogs(t.Context(), s.db, daysAgo(30))
				if err != nil {
					t.Fatalf("CountPrunableAuditLogs: %v", err)
				}
				pruned := mustPrune(t, s.db, chunk)
				if pruned != tt.wantPruned || counted != tt.wantPruned {
					t.Errorf("dry run counted %d, pruned %d; want both to be %d", counted, pruned, tt.wantPruned)
				}
				assertBatchesIntact(t, s.db, sizes, "after the prune")

				got := auditSummary(t, s.db)
				want := append(slices.Clone(tt.want), "audit.prune/success@0", "audit.prune/success@0")
				if !slices.Equal(got, want) {
					t.Errorf("rows after the prune:\n got  %v\n want %v", got, want)
				}
				// 消した行数は、記録にも同じ値で残る。
				recs := pruneRecords(t, s.db)
				if last := recs[len(recs)-1]; last.Count == nil || *last.Count != tt.wantPruned {
					t.Errorf("the closing record count = %v, want %d", last.Count, tt.wantPruned)
				}
			})
		}
	}
}

// 上限の求め方を、返す id で直接確かめる(DESIGN §10.4「消し方」)。
func TestAuditPruneUpperBound(t *testing.T) {
	t.Parallel()

	before := daysAgo(30).Unix()
	upperOf := func(t *testing.T, db *sql.DB) int64 {
		t.Helper()
		upper, err := auditPruneUpperBound(t.Context(), db, before)
		if err != nil {
			t.Fatalf("auditPruneUpperBound: %v", err)
		}
		return upper
	}
	lastID := func(t *testing.T, db *sql.DB, where string) int64 {
		t.Helper()
		var id int64
		//nolint:gosec // G202: where はこのテストが書いた定数で、外からの入力ではない。
		if err := db.QueryRowContext(t.Context(), `SELECT MAX(id) FROM audit_logs WHERE `+where).Scan(&id); err != nil {
			t.Fatalf("find the row (%s): %v", where, err)
		}
		return id
	}

	t.Run("nothing is older than the cutoff", func(t *testing.T) {
		t.Parallel()

		db := newTestStore(t).DB()
		if got := upperOf(t, db); got != 0 {
			t.Errorf("empty table: upper bound = %d, want 0", got)
		}
		mustRecord(t, db, machineAudit(1, "10.0.0.2", daysAgo(30)).machineEntry(ActionAuthMachine, 1))
		mustRecord(t, db, machineAudit(1, "10.0.0.2", daysAgo(1)).machineEntry(ActionAuthMachine, 1))
		if got := upperOf(t, db); got != 0 {
			t.Errorf("only rows at or after the cutoff: upper bound = %d, want 0", got)
		}
		// 上限が 0 でも、刈り込みは通り、2 行の記録を残す(件数は 0)。
		if n := mustPrune(t, db, 10); n != 0 {
			t.Errorf("pruned %d rows, want 0", n)
		}
		if recs := pruneRecords(t, db); len(recs) != 2 || recs[1].Count == nil || *recs[1].Count != 0 {
			t.Errorf("audit.prune records = %+v, want two, the second with count 0", recs)
		}
	})

	t.Run("the newest old row is the head of a batch", func(t *testing.T) {
		t.Parallel()

		s := newAuditSeed(t)
		mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(31), layoutKeys(5)...))
		want := lastID(t, s.db, `at < `+fmt.Sprint(before))
		mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(1), layoutKeys(3)...))
		if got := upperOf(t, s.db); got != want {
			t.Errorf("upper bound = %d, want %d (the last row of the old batch, not its head)", got, want)
		}
	})

	t.Run("the newest old row is a kept row", func(t *testing.T) {
		t.Parallel()

		s := newAuditSeed(t)
		mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100), layoutKeys(5)...))
		mustRecord(t, s.db, s.userAudit(daysAgo(40)).entry(ActionAuthUser, ResultSuccess, nil))
		want := lastID(t, s.db, `action = 'auth.user'`)
		mustRecord(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(1), "RECENT")...)
		if got := upperOf(t, s.db); got != want {
			t.Errorf("upper bound = %d, want %d (the kept row)", got, want)
		}
	})

	// 同じ時刻の「一覧の行」が複数あるときは、id の大きいほうが上限になる
	// (小さいほうで止まると、同じ秒の後ろの行を取り残す)。
	t.Run("rows of the same second", func(t *testing.T) {
		t.Parallel()

		s := newAuditSeed(t)
		for range 3 {
			mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(31), layoutKeys(2)...))
		}
		want := lastID(t, s.db, `1 = 1`)
		if got := upperOf(t, s.db); got != want {
			t.Errorf("upper bound = %d, want %d (the end of the last batch of that second)", got, want)
		}
	})
}

// cancelOnNthDone は、Done が n 回目に呼ばれたときに取り消される context である。
//
// **シグナルの代わりである。** テストのプロセスに本物のシグナルは送らない。
// 時間で取り消すと、どこで止まるかが実行のたびに変わる。呼び出しの回数で
// 決めれば、同じ n は同じ場所で止まる。
type cancelOnNthDone struct {
	context.Context

	cancel context.CancelFunc
	left   atomic.Int64
}

func (c *cancelOnNthDone) Done() <-chan struct{} {
	if c.left.Add(-1) == 0 {
		c.cancel()
	}
	return c.Context.Done()
}

// **どこで止められても、「消した行数」は実際に消えた行数と一致し、batch は
// 欠けない**(DESIGN §10.4「止められたら、そこまでに消した行数を記録して終わる」)。
//
// 止める位置を 1 つずつずらして、全ての位置で同じ性質を確かめる。位置そのもの
// (何回目の Done か)は実装の詳細なので、期待値には使わない。
func TestPruneAuditLogsRecordsTheCountWhereverItIsStopped(t *testing.T) {
	t.Parallel()

	const (
		batches   = 6
		perBatch  = 3
		seeded    = batches * perBatch
		positions = 120
	)
	var partial, completed atomic.Int64
	t.Run("positions", func(t *testing.T) {
		t.Parallel()
		for n := 1; n <= positions; n++ {
			t.Run(fmt.Sprintf("stopped at call %d", n), func(t *testing.T) {
				t.Parallel()

				s := newAuditSeed(t)
				for i := range batches {
					mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100-i), layoutKeys(perBatch)...))
				}
				sizes := batchSizes(t, s.db)

				inner, cancel := context.WithCancel(t.Context())
				defer cancel()
				ctx := &cancelOnNthDone{Context: inner, cancel: cancel}
				ctx.left.Store(int64(n))

				got, err := PruneAuditLogs(ctx, s.db, daysAgo(30), pruneClock, 1)

				gone := int64(seeded - countAuditLogs(t, s.db, ActionSecretRead))
				if got != gone {
					t.Errorf("PruneAuditLogs returned %d, but %d rows are gone (err = %v)", got, gone, err)
				}
				assertBatchesIntact(t, s.db, sizes, "after the stop")

				recs := pruneRecords(t, s.db)
				switch {
				case err == nil:
					completed.Add(1)
					if gone != seeded {
						t.Errorf("no error although only %d of %d rows are gone", gone, seeded)
					}
					if len(recs) != 2 || recs[1].Result != string(ResultSuccess) {
						t.Errorf("audit.prune records = %+v, want started / finished", recs)
					}
				case len(recs) == 0:
					// 「始めた」行を書く前に止まった。何も消えていない。
					if gone != 0 {
						t.Errorf("%d rows are gone without any audit.prune record (err = %v)", gone, err)
					}
				case len(recs) == 1:
					// 「始めた」行の INSERT が確定したのに、ドライバが取り消しの
					// エラーを返した(取り消しが文の完了と重なった)。終わりの行は
					// 無いが、何も消えていないので、安全な側である。
					if gone != 0 || recs[0].Count != nil {
						t.Errorf("%d rows are gone with only an opening audit.prune record (err = %v)", gone, err)
					}
				default:
					if gone > 0 && gone < seeded {
						partial.Add(1)
					}
					if len(recs) != 2 {
						t.Fatalf("%d audit.prune rows after a stop, want 2 (started / stopped); err = %v", len(recs), err)
					}
					if recs[1].Result != string(ResultFailure) || recs[1].Count == nil || *recs[1].Count != gone {
						recorded := int64(-1)
						if recs[1].Count != nil {
							recorded = *recs[1].Count
						}
						t.Errorf("the closing record = %s count %d, want failure with count %d (err = %v)",
							recs[1].Result, recorded, gone, err)
					}
				}
			})
		}
	})
	// 並列の子が全て終わってから数える。
	t.Cleanup(func() {
		if partial.Load() == 0 {
			t.Errorf("no position stopped the prune midway (%d of %d ran to the end); the test no longer checks a partial run",
				completed.Load(), positions)
		}
	})
}

// lateCancelConnector は、**DELETE が確定した直後に取り消しが届く**状況を
// 再現する接続を作る。
//
// 本物のドライバ(modernc.org/sqlite)は、文の実行中に context が取り消されると、
// 文が最後まで走って確定していても `ctx.Err()` を返す(stmt.go の exec。割り込みが
// 文の完了と重なったとき)。上の「止める位置をずらす」テストは、その重なりを
// 本物のドライバで踏むが、重なるかどうかは goroutine の順序で決まる。ここでは
// 同じ結果(確定したのにエラーが返る)を、決まった位置で起こす。
type lateCancelConnector struct {
	dsn    string
	inner  driver.Driver
	cancel context.CancelFunc
	// 何回目の DELETE で取り消すか(残りの回数)。
	deletes atomic.Int64
}

func (c *lateCancelConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &lateCancelConn{Conn: conn, owner: c}, nil
}

func (c *lateCancelConnector) Driver() driver.Driver { return c.inner }

type lateCancelConn struct {
	driver.Conn

	owner *lateCancelConnector
}

func (c *lateCancelConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	res, err := execer.ExecContext(ctx, query, args)
	if err == nil && strings.HasPrefix(strings.TrimSpace(query), "DELETE") && c.owner.deletes.Add(-1) == 0 {
		// 文は確定している。ここで取り消しが届く。渡された context が取り消しを
		// 受けるものなら、本物のドライバと同じく、結果を捨ててエラーを返す。
		c.owner.cancel()
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
	}
	return res, err
}

func (c *lateCancelConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, query, args)
}

func (c *lateCancelConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, errors.New("the wrapped connection cannot begin a transaction with a context")
	}
	return beginner.BeginTx(ctx, opts)
}

// **DELETE が確定したのと同時に止められても、その回に消えた行は「消した行数」に
// 入る。** 入らないと、記録より多くの行が消えていることになる(DESIGN §10.4
// 「止められたら、そこまでに消した行数を記録して終わる」)。
func TestPruneAuditLogsCountsADeleteThatCommittedAsItWasStopped(t *testing.T) {
	t.Parallel()

	const (
		batches  = 4
		perBatch = 3
	)
	s := newAuditSeed(t)
	for i := range batches {
		mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100-i), layoutKeys(perBatch)...))
	}
	path := queryStrings(t, s.db, `SELECT file FROM pragma_database_list WHERE name = 'main'`)[0]

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	connector := &lateCancelConnector{dsn: dataSourceName(path), inner: s.db.Driver(), cancel: cancel}
	connector.deletes.Store(2) // 2 回目の DELETE(2 つ目の batch)で止める
	db := sql.OpenDB(connector)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	got, err := PruneAuditLogs(ctx, db, daysAgo(30), pruneClock, 1)
	if err == nil {
		t.Fatal("PruneAuditLogs returned no error although it was stopped")
	}
	gone := int64(batches*perBatch - countAuditLogs(t, s.db, ActionSecretRead))
	if gone != 2*perBatch {
		t.Fatalf("%d rows are gone, want %d (the test assumes the second delete commits)", gone, 2*perBatch)
	}
	if got != gone {
		t.Errorf("PruneAuditLogs returned %d, but %d rows are gone (err = %v)", got, gone, err)
	}
	recs := pruneRecords(t, s.db)
	if len(recs) != 2 || recs[1].Count == nil {
		t.Fatalf("audit.prune records = %+v, want started / stopped with a count", recs)
	}
	if recs[1].Result != string(ResultFailure) || *recs[1].Count != gone {
		t.Errorf("the closing record = %s count %d, want failure with count %d", recs[1].Result, *recs[1].Count, gone)
	}
}

// **終わりの行が書けなかったときは、消した行数と一緒にエラーを返す。**
// 行は消えているので、成功として返すと「記録の無い削除」を見逃す。
func TestPruneAuditLogsReportsAClosingRecordThatCannotBeWritten(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecordBatch(t, s.db, s.readEntries(s.prodID, "prod", daysAgo(100), "A", "B", "C"))
	// 件数を持つ行(終わりの行)だけを失敗させる。
	if _, err := s.db.ExecContext(t.Context(), `
		CREATE TRIGGER no_closing_record BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'audit.prune' AND NEW.detail LIKE '%"count"%'
		BEGIN SELECT RAISE(ABORT, 'audit write failed'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	n, err := PruneAuditLogs(t.Context(), s.db, daysAgo(30), pruneClock, 100)
	if err == nil {
		t.Fatal("PruneAuditLogs succeeded although its closing record could not be written")
	}
	if n != 3 {
		t.Errorf("n = %d, want 3 (the rows are gone; the caller must be able to report the number)", n)
	}
	// 「始めた」行は残る(終わりの行が無いことで、異常が分かる)。
	if recs := pruneRecords(t, s.db); len(recs) != 1 || recs[0].Count != nil {
		t.Errorf("audit.prune records = %+v, want only the opening record", recs)
	}
}

// **allowlist は 2 つの操作だけである。** 記録できる全ての操作について、machine
// が実行者の成功の行を古い時刻で置き、消えるのが secret.read と auth.machine
// だけであることを確かめる(audit.prune 自身も、machine が実行者でも消えない)。
//
// 操作を足したときに、このテストを直さずに刈り込みの対象が増えることは無い。
func TestPruneAuditLogsAllowlistIsExactlyTwoActions(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	actions := make([]string, 0, len(auditActions))
	for a := range auditActions {
		actions = append(actions, string(a))
	}
	slices.Sort(actions)

	// newAuditSeed の行(400 日前)より新しくする。古くすると、時刻の順と id の
	// 順が逆になり、上限の外に出る。
	old := daysAgo(100)
	reason := ReasonForbidden
	for _, a := range actions {
		mustRecord(t, s.db,
			machineAudit(s.machineID, "10.0.0.2", old).entry(Action(a), ResultSuccess, nil),
			machineAudit(s.machineID, "10.0.0.2", old).entry(Action(a), ResultFailure, &AuditDetail{Reason: &reason}),
			s.userAudit(old).entry(Action(a), ResultSuccess, nil),
			cliAudit(old).entry(Action(a), ResultSuccess, nil),
		)
	}

	if n := mustPrune(t, s.db, 3); n != 2 {
		t.Errorf("pruned %d rows, want 2 (one success by the machine for each of the two actions)", n)
	}
	var want []string
	for _, a := range actions {
		if a != "secret.read" && a != "auth.machine" {
			want = append(want, a)
		}
	}
	got := queryStrings(t, s.db, fmt.Sprintf(
		`SELECT action FROM audit_logs WHERE actor_machine_id IS NOT NULL AND result = 'success' AND at = %d ORDER BY action`, old.Unix()))
	if !slices.Equal(got, want) {
		t.Errorf("successes by the machine left after the prune:\n got  %v\n want %v", got, want)
	}
	// 失敗、人、CLI の行は、どの操作でも残る。
	if got := queryStrings(t, s.db, fmt.Sprintf(
		`SELECT COUNT(*) FROM audit_logs WHERE at = %d AND NOT (actor_machine_id IS NOT NULL AND result = 'success')`, old.Unix())); got[0] != fmt.Sprint(3*len(actions)) {
		t.Errorf("%s other rows left, want %d (3 for each action)", got[0], 3*len(actions))
	}
}

// ---- 監査の detail ----

// before と count は、RecordAudit を通して往復する。count は int64 である
// (数百万行を消す実行でも、32 bit の環境で桁が落ちない)。
func TestAuditDetailBeforeAndCountRoundTrip(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	before, count := int64(1)<<40, int64(5_000_000_000)
	detail := &AuditDetail{Before: &before, Count: &count}
	mustRecord(t, db, cliAudit(pruneNow).entry(ActionAuditPrune, ResultSuccess, detail))
	// 呼び出し側の detail は書き換えない(AGENTS.md の教訓: entry が呼び出し側を壊した)。
	if detail.Via != nil {
		t.Errorf("entry changed the caller's detail (via = %q)", *detail.Via)
	}

	raw := queryStrings(t, db, `SELECT detail FROM audit_logs WHERE action = 'audit.prune'`)
	if want := []string{`{"via":"cli","count":5000000000,"before":1099511627776}`}; !slices.Equal(raw, want) {
		t.Errorf("stored detail = %v, want %v", raw, want)
	}
	recs := pruneRecords(t, db)
	if len(recs) != 1 || recs[0].Before == nil || *recs[0].Before != before || recs[0].Count == nil || *recs[0].Count != count {
		t.Fatalf("decoded detail = %+v, want before %d and count %d", recs, before, count)
	}
	// CLI の行は、送信元も実行者の id も持たない(誰かは分からない)。
	if got := queryStrings(t, db, `
		SELECT COUNT(*) FROM audit_logs WHERE action = 'audit.prune' AND actor = 'anonymous'
		AND remote_addr IS NULL AND actor_user_id IS NULL AND actor_machine_id IS NULL AND target IS NULL`); got[0] != "1" {
		t.Errorf("the cli row carries an address, an actor id or a target")
	}
}

// via は 3 つの値に限る。"cli" を足しても、似た文字列は通さない。
func TestAuditDetailViaAcceptsOnlyKnownValues(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	entry := func(via string) AuditEntry {
		return AuditEntry{
			At: pruneNow, Actor: ActorAnonymous, Action: ActionAuditPrune, Result: ResultSuccess,
			Detail: &AuditDetail{Via: &via},
		}
	}
	for _, via := range []string{"cli", "socket", "web"} {
		if err := RecordAudit(t.Context(), db, entry(via)); err != nil {
			t.Errorf("via %q was rejected: %v", via, err)
		}
	}
	for _, via := range []string{"", "CLI", "cli ", " cli", "cli\n", "command", "cli,web"} {
		if err := RecordAudit(t.Context(), db, entry(via)); err == nil {
			t.Errorf("via %q was accepted", via)
		}
	}
	if n := countAuditLogs(t, db, ActionAuditPrune); n != 3 {
		t.Errorf("%d rows were written, want 3 (rejected values must not reach the table)", n)
	}
}

// ---- コマンドと、サーバーとの噛み合わせ ----

// main の振り分けから届く(サブコマンドを足したが繋ぎ忘れた、を防ぐ)。
func TestRunDispatchesAuditPrune(t *testing.T) {
	t.Parallel()

	err := run(t.Context(), []string{"audit-prune"})
	if err == nil || !strings.Contains(err.Error(), "--keep-days is required") {
		t.Errorf("run audit-prune = %v, want the command's own error about --keep-days", err)
	}
	if !strings.Contains(usage, "audit-prune --keep-days") {
		t.Error("the usage text does not mention audit-prune")
	}
}

// **スキーマの版が合わない DB には触らない**(--dry-run でも開かない)。
// 版が違えば、列や索引が想定と違いうる。
func TestCmdAuditPruneRefusesAMismatchingSchema(t *testing.T) {
	t.Parallel()

	for name, version := range map[string]int{"newer": schemaVersion + 1, "older": schemaVersion - 1} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "hokora.db")
			store := newTestStoreAt(t, path)
			db := store.DB()
			// コマンドは実時刻を使うので、行も実時刻から作る。
			old := time.Now().Add(-100 * 24 * time.Hour)
			mustRecord(t, db, machineAudit(1, "10.0.0.2", old).machineEntry(ActionAuthMachine, 1))
			if _, err := db.ExecContext(t.Context(), fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
				t.Fatalf("set user_version: %v", err)
			}
			snapshot := func() []string {
				return queryStrings(t, db, `SELECT id || ':' || action || ':' || at FROM audit_logs ORDER BY id`)
			}
			before := snapshot()

			for _, args := range [][]string{
				{"-db", path, "-keep-days", "30"},
				{"-db", path, "-keep-days", "30", "-dry-run"},
			} {
				err := cmdAuditPrune(t.Context(), args)
				if err == nil || !strings.Contains(err.Error(), "schema version") {
					t.Errorf("cmdAuditPrune%v = %v, want a refusal that names the schema version", args, err)
				}
			}
			if after := snapshot(); !slices.Equal(before, after) || len(after) != 1 {
				t.Errorf("the refused runs changed the audit log:\nbefore %v\nafter  %v", before, after)
			}
			assertUserVersion(t, db, version)
		})
	}
}

// dumpTables は、audit_logs 以外の全ての表の中身を、表ごとに返す。
func dumpTables(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()

	out := map[string][]string{}
	for _, table := range queryStrings(t, db, `
		SELECT name FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'audit_logs' ORDER BY name`) {
		out[table] = dumpTable(t, db, table)
	}
	return out
}

func dumpTable(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	//nolint:gosec // G202: 表の名前は sqlite_master から取ったもので、外からの入力ではない(名前は引数にできない)。
	rows, err := db.QueryContext(t.Context(), `SELECT * FROM "`+table+`" ORDER BY rowid`)
	if err != nil {
		t.Fatalf("dump %s: %v", table, err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		t.Fatalf("dump %s: %v", table, err)
	}
	var out []string
	for rows.Next() {
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			t.Fatalf("dump %s: %v", table, err)
		}
		out = append(out, fmt.Sprintf("%v=%v", columns, values))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("dump %s: %v", table, err)
	}
	return out
}

// **本物の Machine API が書いた行を刈り込み、その後もサーバーと監査ログ画面が
// 動く。**
//
// 他のテストは監査行を手で組み立てている。ここでは API が実際に書く行(認証、
// bulk fetch、単一取得、拒否)を対象にして、次を確かめる。
//
//   - 消えるのは成功の行だけで、拒否の行は残る
//   - **監査ログ以外の表は 1 行も変わらない**(secret、鍵、machine、grant、
//     session、user。`machines.last_auth_at` も)
//   - 発行済みのトークンは使え続ける(刈り込みは認可に関わらない)
//   - 監査ログ画面は描画でき、刈り込みの記録が出て、消した読み取りは出ない
func TestAuditPruneAfterRealMachineTraffic(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	db := f.store.DB()
	ui, err := newUIServer(f.vault, discardLogger(), newRateLimiter(unsealRate, 1))
	if err != nil {
		t.Fatalf("newUIServer: %v", err)
	}
	ui.now = func() time.Time { return vaultNow }
	screen := &uiFixture{ui: ui, vault: f.vault, store: f.store, mk: f.mk}
	screen.userID = newTestUser(t, f.store)
	screen.rawSess = newTestSession(t, f.store, screen.userID)
	page := func(path string) string {
		t.Helper()
		w := screen.get(t, path)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, w.Code)
		}
		return w.Body.String()
	}

	// API の時計は vaultNow で、刈り込みの「いま」(pruneNow)の 400 日前である。
	// 行は最初から期間を過ぎている。
	token := f.token(t)
	bulk := secretsPath(testProjectSlug, testEnvSlug)
	if w := f.do(t, http.MethodGet, bulk, token, nil); w.Code != http.StatusOK {
		t.Fatalf("bulk fetch = %d, want 200", w.Code)
	}
	if w := f.do(t, http.MethodGet, "/v1/secrets/DATABASE_URL?project=myapp&env=prod", token, nil); w.Code != http.StatusOK {
		t.Fatalf("single fetch = %d, want 200", w.Code)
	}
	// grant の無い environment への読み取りは拒否され、失敗として残る。
	insertEnvironment(t, db, f.projectID, "staging", false)
	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, "staging"), token, nil); w.Code != http.StatusForbidden {
		t.Fatalf("fetch without a grant = %d, want 403", w.Code)
	}

	summary := func() []string {
		return queryStrings(t, db, `SELECT action || '/' || result FROM audit_logs WHERE action <> 'audit.prune' ORDER BY id`)
	}
	wantBefore := []string{
		"unseal.attempt/success", "machine.create/success", "auth.machine/success",
		"secret.read/success", "secret.read/success", "secret.read/success", "secret.read/failure",
	}
	if got := summary(); !slices.Equal(got, wantBefore) {
		t.Fatalf("audit rows written by the API = %v, want %v (the test assumes this traffic)", got, wantBefore)
	}
	const oldKey = `<span class="key">myapp/prod/API_TOKEN</span>`
	if !strings.Contains(page("/ui/audit?action=secret.read"), oldKey) {
		t.Fatalf("the audit page does not show the bulk fetch before the prune (looked for %s)", oldKey)
	}

	tables := dumpTables(t, db)
	for _, table := range []string{"items", "item_versions", "keyring", "machine_grants", "machines", "sessions", "users"} {
		if len(tables[table]) == 0 {
			t.Fatalf("table %s is empty before the prune; the comparison would check nothing", table)
		}
	}
	if !strings.Contains(strings.Join(tables["machines"], "\n"), fmt.Sprint(vaultNow.Unix())) {
		t.Fatalf("machines does not carry last_auth_at before the prune: %v", tables["machines"])
	}

	if n := mustPrune(t, db, 2); n != 4 {
		t.Errorf("pruned %d rows, want 4 (the login, the bulk fetch of 2 and the single fetch)", n)
	}

	if got, want := summary(), []string{"unseal.attempt/success", "machine.create/success", "secret.read/failure"}; !slices.Equal(got, want) {
		t.Errorf("rows after the prune = %v, want %v", got, want)
	}
	after := dumpTables(t, db)
	if len(after) != len(tables) {
		t.Errorf("the set of tables changed: %d before, %d after", len(tables), len(after))
	}
	for table, rows := range tables {
		if !slices.Equal(rows, after[table]) {
			t.Errorf("the prune changed table %s:\nbefore %v\nafter  %v", table, rows, after[table])
		}
	}

	// 画面: 刈り込みの記録が出て、操作で絞り込める。消した読み取りは出ない。
	wantDetail := fmt.Sprintf(`&#34;via&#34;:&#34;cli&#34;,&#34;count&#34;:4,&#34;before&#34;:%d`, daysAgo(30).Unix())
	for _, path := range []string{"/ui/audit", "/ui/audit?action=audit.prune"} {
		if body := page(path); !strings.Contains(body, wantDetail) {
			t.Errorf("GET %s does not show the closing audit.prune record (looked for %s)", path, wantDetail)
		}
	}
	reads := page("/ui/audit?action=secret.read")
	if strings.Contains(reads, oldKey) || strings.Contains(reads, "myapp/prod/DATABASE_URL") {
		t.Error("the audit page still shows the pruned reads")
	}
	if !strings.Contains(reads, `&#34;reason&#34;:&#34;forbidden&#34;`) {
		t.Error("the audit page lost the denied read")
	}

	// サーバーは動き続ける: 同じトークンで読め、その読み取りは画面に出る。
	if w := f.do(t, http.MethodGet, bulk, token, nil); w.Code != http.StatusOK {
		t.Fatalf("bulk fetch after the prune = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	if !strings.Contains(page("/ui/audit?action=secret.read"), oldKey) {
		t.Error("the audit page does not show a bulk fetch made after the prune")
	}
}
