package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// auditSeed は一覧のテストに使う、主体と対象の揃った DB である。
type auditSeed struct {
	db        *sql.DB
	userID    int64
	machineID int64
	projectID int64
	prodID    int64 // myapp/prod
	stagingID int64 // myapp/staging
}

func newAuditSeed(t *testing.T) auditSeed {
	t.Helper()

	store := newTestStore(t)
	db := store.DB()
	s := auditSeed{db: db}
	s.userID = newTestUser(t, store)
	var err error
	// machine.create の監査行は、各テストの前提を単純にするため別の時刻にしない
	// (件数を数えるテストは、seed 直後の行数を基準にする)。
	if s.machineID, _, err = CreateMachine(t.Context(), db, "app-prod", "web01", secretAudit()); err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	s.projectID = insertProject(t, db, "myapp", false)
	s.prodID = insertEnvironment(t, db, s.projectID, "prod", false)
	s.stagingID = insertEnvironment(t, db, s.projectID, "staging", false)
	return s
}

// readEntries は machine による secret.read の行を n 件作る(1 回の bulk fetch)。
func (s auditSeed) readEntries(envID int64, envSlug string, at time.Time, keys ...string) []AuditEntry {
	ac := machineAudit(s.machineID, "10.0.0.2", at)
	entries := make([]AuditEntry, 0, len(keys))
	for i, key := range keys {
		target := "myapp/" + envSlug + "/" + key
		version := int64(i + 1)
		entry := ac.entry(ActionSecretRead, ResultSuccess, &AuditDetail{Version: &version})
		entry.Target = &target
		entry.TargetProjectID = &s.projectID
		entry.TargetEnvironmentID = &envID
		entry.TargetMachineID = &s.machineID
		entries = append(entries, entry)
	}
	return entries
}

func (s auditSeed) userAudit(at time.Time) auditCtx {
	return userAudit(s.userID, "10.8.0.9", at)
}

func mustRecord(t *testing.T, db *sql.DB, entries ...AuditEntry) {
	t.Helper()
	for _, e := range entries {
		if err := RecordAudit(t.Context(), db, e); err != nil {
			t.Fatalf("RecordAudit(%s): %v", e.Action, err)
		}
	}
}

func mustList(t *testing.T, db *sql.DB, q AuditQuery) AuditPage {
	t.Helper()
	if q.Limit == 0 {
		q.Limit = 100
	}
	page, err := ListAuditLogs(t.Context(), db, q)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	return page
}

// **bulk fetch の行は、一覧では先頭行 1 件に畳まれる。行そのものは key の数だけ
// DB にある**(ルール 23)。畳むのは表示だけである。
func TestListAuditLogsFoldsABatchIntoItsHeadRow(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	at := vaultNow.Add(time.Hour)
	if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", at, "API_TOKEN", "DATABASE_URL", "SMTP_PASSWORD")); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	// 同じ machine の単一取得。batch にならない。
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", at.Add(time.Second), "DATABASE_URL")...)

	if n := countAuditLogs(t, s.db, ActionSecretRead); n != 4 {
		t.Fatalf("secret.read rows in the database = %d, want 4 (one per key)", n)
	}

	page := mustList(t, s.db, AuditQuery{Filter: AuditFilter{Action: ActionSecretRead}})
	if len(page.Rows) != 2 {
		t.Fatalf("listed %d rows, want 2 (the single read and the batch as one row)", len(page.Rows))
	}

	single, batch := page.Rows[0], page.Rows[1]
	// **1 件だけの読み取りも、bulk fetch と同じ形で出る。** 対象列は 'project/env'
	// までで、key と detail は畳んだ中の 1 件になる。
	if single.BatchSize != 1 || len(single.Batch) != 1 || single.Batch[0].Target != "myapp/prod/DATABASE_URL" {
		t.Errorf("single read: size %d, items %v; want the key as the only item", single.BatchSize, single.Batch)
	}
	if single.Detail != "" || !strings.Contains(single.Batch[0].Detail, `"version":1`) {
		t.Errorf("single read detail = %q / item detail = %q, want the detail on the item only", single.Detail, single.Batch[0].Detail)
	}
	// 実行者は「実行者」列にあるので、対象列では繰り返さない。
	if single.Target != "myapp/prod" {
		t.Errorf("single read target = %q, want %q", single.Target, "myapp/prod")
	}

	// 先頭行自身を含む全ての key が、書かれた順に並ぶ。
	var targets []string
	for _, item := range batch.Batch {
		targets = append(targets, item.Target)
	}
	if want := []string{"myapp/prod/API_TOKEN", "myapp/prod/DATABASE_URL", "myapp/prod/SMTP_PASSWORD"}; !slices.Equal(targets, want) {
		t.Errorf("batch items = %v, want %v", targets, want)
	}
	// detail(version)は key ごとに違うので、行ではなく各 item に付く。
	if batch.Detail != "" || !strings.Contains(batch.Batch[1].Detail, `"version":2`) {
		t.Errorf("batch detail = %q / item detail = %q, want the version on each item only", batch.Detail, batch.Batch[1].Detail)
	}
	// 対象列は batch 全体に共通する部分だけ(先頭行の key を代表にしない)。
	if batch.Target != "myapp/prod" {
		t.Errorf("batch target = %q, want %q", batch.Target, "myapp/prod")
	}
}

// **対象列は、実行者自身を繰り返さない。ただし対象が実行者自身だけなら残す。**
//
// machine の secret.read は target_machine_id に自分を記録する。そのまま出すと
// 「実行者」列と同じ名前が対象列にも並び、どこを読んだのかが埋もれる。一方、
// 自分のログインのように対象が自分だけの行を空欄にすると、「対象なし」と
// 区別できなくなる。他人が対象の行(grant、無効化)は、もちろん出す。
func TestListAuditLogsTargetDoesNotRepeatTheActor(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	at := vaultNow.Add(time.Hour)
	self := fmt.Sprintf("web01 (machine:%d)", s.machineID)
	admin := fmt.Sprintf("%s (user:%d)", testUsername, s.userID)

	// machine が自分で認証した(対象は自分だけ)。
	mustRecord(t, s.db, machineAudit(s.machineID, "10.0.0.2", at).machineEntry(ActionAuthMachine, s.machineID))
	// machine が読んだ(対象は自分 + key)。
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", at.Add(time.Second), "DATABASE_URL")...)
	// user が、その machine に grant を付けた(対象は他人 + 環境)。
	grant := s.userAudit(at.Add(2*time.Second)).machineEntry(ActionGrantCreate, s.machineID)
	grant.TargetEnvironmentID = &s.prodID
	mustRecord(t, s.db, grant)
	// user が自分のパスワードを変えた(対象は自分だけ)。
	mustRecord(t, s.db, s.userAudit(at.Add(3*time.Second)).userEntry(ActionUserPasswordChange, s.userID))
	// user が key を表示した(対象は key だけ。user は対象に記録されない)。
	reveal := s.userAudit(at.Add(4*time.Second)).entry(ActionSecretReveal, ResultSuccess, nil)
	target := "myapp/prod/DATABASE_URL"
	reveal.Target = &target
	mustRecord(t, s.db, reveal)

	want := map[string]string{
		string(ActionAuthMachine):        self,
		string(ActionSecretRead):         "myapp/prod",
		string(ActionGrantCreate):        self + " → myapp/prod",
		string(ActionUserPasswordChange): admin,
		string(ActionSecretReveal):       "myapp/prod",
	}
	seen := map[string]bool{}
	for _, row := range mustList(t, s.db, AuditQuery{Filter: AuditFilter{From: ptr(at)}}).Rows {
		seen[row.Action] = true
		if row.Target != want[row.Action] {
			t.Errorf("%s: target = %q, want %q", row.Action, row.Target, want[row.Action])
		}
	}
	for action := range want {
		if !seen[action] {
			t.Errorf("the %s row is missing from the list", action)
		}
	}
}

// key を対象にしない行は、detail を行に持ったままである(画面は「詳細」として畳む)。
func TestListAuditLogsKeepsTheDetailOfRowsWithoutAKey(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	at := vaultNow.Add(time.Hour)
	reason := ReasonForbidden
	// 拒否された読み取りは target を記録しない(key の行にならない)。
	denied := machineAudit(s.machineID, "10.0.0.2", at).entry(ActionSecretRead, ResultFailure, &AuditDetail{Reason: &reason})
	denied.TargetMachineID = &s.machineID
	mustRecord(t, s.db, denied)

	rows := mustList(t, s.db, AuditQuery{Filter: AuditFilter{Result: ResultFailure}}).Rows
	if len(rows) != 1 {
		t.Fatalf("listed %d rows, want 1", len(rows))
	}
	if rows[0].BatchSize != 0 || len(rows[0].Batch) != 0 {
		t.Errorf("a denied read is shown as a key row: size %d, items %v", rows[0].BatchSize, rows[0].Batch)
	}
	if !strings.Contains(rows[0].Detail, `"reason":"forbidden"`) {
		t.Errorf("detail = %q, want the reason to stay on the row", rows[0].Detail)
	}
	// 1 件だけの行は batch の画面を持たない。
	if _, err := ListAuditBatch(t.Context(), s.db, rows[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("ListAuditBatch on a row without a batch: err = %v, want ErrNotFound", err)
	}
}

// **batch は 1 件として数える。** 30 key の bulk fetch が 1 ページを埋めて
// 他の操作を押し出すのが、この変更で直したい問題である(#22)。
func TestListAuditLogsCountsABatchAsOneRow(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	base := vaultNow.Add(time.Hour)
	mustRecord(t, s.db, s.userAudit(base).entry(ActionAuthUser, ResultSuccess, nil))
	keys := make([]string, 30)
	for i := range keys {
		keys[i] = fmt.Sprintf("KEY_%02d", i)
	}
	for i := range 3 {
		if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", base.Add(time.Duration(i+1)*time.Second), keys...)); err != nil {
			t.Fatalf("RecordAuditBatch: %v", err)
		}
	}

	page := mustList(t, s.db, AuditQuery{Limit: 4})
	if len(page.Rows) != 4 {
		t.Fatalf("listed %d rows, want 4", len(page.Rows))
	}
	// 3 回の bulk fetch(90 行)の後ろに、ログインがまだ見えている。
	if got := page.Rows[3].Action; got != string(ActionAuthUser) {
		t.Errorf("rows[3].Action = %q, want the login to stay visible behind three bulk fetches", got)
	}
	for i, row := range page.Rows[:3] {
		if len(row.Batch) != len(keys) {
			t.Errorf("rows[%d] has %d batch items, want %d", i, len(row.Batch), len(keys))
		}
	}
}

func rowIDs(rows []AuditRow) []int64 {
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return ids
}

// **ページを端から端まで歩いて、全ての行がちょうど 1 回ずつ出る。**
//
// 同じ秒の行が複数ページにまたがるように作る(at だけを位置にすると、同じ秒の
// 残りを飛ばすか、繰り返す)。古い方へ歩き切ったら、新しい方へ歩いて戻る。
func TestListAuditLogsPagesThroughEveryRowExactlyOnce(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	for i := range 23 {
		// 7 行ごとに 1 秒進む。ページ(5 件)の境界が同じ秒の途中に来る。
		at := vaultNow.Add(time.Duration(i/7) * time.Second)
		mustRecord(t, s.db, s.userAudit(at).entry(ActionAuthUser, ResultSuccess, nil))
	}
	all := rowIDs(mustList(t, s.db, AuditQuery{Limit: 100}).Rows)

	const size = 5
	var walked []int64
	page := mustList(t, s.db, AuditQuery{Limit: size})
	if page.Newer != nil {
		t.Error("the newest page has a link to newer rows")
	}
	pages := 1
	for {
		walked = append(walked, rowIDs(page.Rows)...)
		if page.Older == nil {
			break
		}
		page = mustList(t, s.db, AuditQuery{Limit: size, Before: page.Older})
		if page.Newer == nil {
			t.Errorf("page %d has no link back to newer rows", pages+1)
		}
		pages++
	}
	if !slices.Equal(walked, all) {
		t.Errorf("walking older:\n got  %v\n want %v", walked, all)
	}

	// 新しい方へ戻る。最後に最新のページと同じ行に戻る。
	var back []int64
	for {
		back = append(slices.Clone(rowIDs(page.Rows)), back...)
		if page.Newer == nil {
			break
		}
		page = mustList(t, s.db, AuditQuery{Limit: size, After: page.Newer})
	}
	if !slices.Equal(back, all) {
		t.Errorf("walking newer:\n got  %v\n want %v", back, all)
	}
}

// 位置の先に行が無ければ、空のページを返す(リンクを手で書き換えた場合など)。
func TestListAuditLogsBeyondTheEnds(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	for _, q := range []AuditQuery{
		{Before: &AuditCursor{At: 0, ID: 1}},
		{After: &AuditCursor{At: vaultNow.Add(24 * time.Hour).Unix(), ID: 1}},
	} {
		page := mustList(t, s.db, q)
		if len(page.Rows) != 0 || page.Older != nil || page.Newer != nil {
			t.Errorf("query %+v: got %d rows, older %v, newer %v; want an empty page", q, len(page.Rows), page.Older, page.Newer)
		}
	}
}

// 絞り込みの各条件が、合う行だけを返す。
func TestListAuditLogsFilters(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	day := func(d int) time.Time { return vaultNow.Add(time.Duration(d) * 24 * time.Hour) }

	// 絞り込みの対象にする行。seed の machine.create(anonymous)とは時刻を離す。
	login := s.userAudit(day(1)).entry(ActionAuthUser, ResultSuccess, nil)
	reason := ReasonInvalidCredentials
	loginFailed := auditCtx{Actor: ActorAnonymous, Via: ViaWeb, Now: day(2)}.entry(ActionAuthUser, ResultFailure, &AuditDetail{Reason: &reason})
	mustRecord(t, s.db, login, loginFailed)
	if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", day(3), "A", "B")); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	mustRecord(t, s.db, s.readEntries(s.stagingID, "staging", day(4), "C")...)

	// 期待値は「操作@日」で書く。
	label := func(r AuditRow) string {
		return fmt.Sprintf("%s@%d", r.Action, int(r.At.Sub(vaultNow).Hours()/24))
	}
	tests := []struct {
		name   string
		filter AuditFilter
		want   []string
	}{
		{"no filter", AuditFilter{}, []string{"secret.read@4", "secret.read@3", "auth.user@2", "auth.user@1", "machine.create@0"}},
		{"from", AuditFilter{From: ptr(day(3))}, []string{"secret.read@4", "secret.read@3"}},
		{"to is exclusive", AuditFilter{To: ptr(day(2))}, []string{"auth.user@1", "machine.create@0"}},
		{"from and to", AuditFilter{From: ptr(day(1)), To: ptr(day(3))}, []string{"auth.user@2", "auth.user@1"}},
		{"actor user", AuditFilter{ActorUserID: &s.userID}, []string{"auth.user@1"}},
		{"actor machine", AuditFilter{ActorMachineID: &s.machineID}, []string{"secret.read@4", "secret.read@3"}},
		{"actor anonymous", AuditFilter{ActorAnonymous: true}, []string{"auth.user@2", "machine.create@0"}},
		{"action", AuditFilter{Action: ActionAuthUser}, []string{"auth.user@2", "auth.user@1"}},
		{"result", AuditFilter{Result: ResultFailure}, []string{"auth.user@2"}},
		{"environment", AuditFilter{EnvironmentID: &s.prodID}, []string{"secret.read@3"}},
		{"combined", AuditFilter{ActorMachineID: &s.machineID, EnvironmentID: &s.stagingID, Action: ActionSecretRead}, []string{"secret.read@4"}},
		{"nothing matches", AuditFilter{ActorUserID: &s.userID, Result: ResultFailure}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []string
			for _, r := range mustList(t, s.db, AuditQuery{Filter: tt.filter}).Rows {
				got = append(got, label(r))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	// **絞り込んでも batch は畳まれたまま**で、後続行が単独の行として出てこない。
	page := mustList(t, s.db, AuditQuery{Filter: AuditFilter{EnvironmentID: &s.prodID}})
	if len(page.Rows) != 1 || len(page.Rows[0].Batch) != 2 {
		t.Errorf("filtering by environment: %d rows, batch %v; want the batch as one row with 2 items", len(page.Rows), page.Rows)
	}
}

// 絞り込みはページ送りの間も保たれ、合わない行が混ざらない。
func TestListAuditLogsPagesWithinAFilter(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	for i := range 6 {
		at := vaultNow.Add(time.Duration(i+1) * time.Minute)
		mustRecord(t, s.db, s.userAudit(at).entry(ActionAuthUser, ResultSuccess, nil))
		mustRecord(t, s.db, s.userAudit(at).entry(ActionLogout, ResultSuccess, nil))
	}

	filter := AuditFilter{Action: ActionLogout}
	var seen int
	page := mustList(t, s.db, AuditQuery{Filter: filter, Limit: 4})
	for {
		for _, r := range page.Rows {
			if r.Action != string(ActionLogout) {
				t.Fatalf("a %s row leaked into a page filtered by %s", r.Action, ActionLogout)
			}
			seen++
		}
		if page.Older == nil {
			break
		}
		page = mustList(t, s.db, AuditQuery{Filter: filter, Limit: 4, Before: page.Older})
	}
	if seen != 6 {
		t.Errorf("saw %d logout rows across the pages, want 6", seen)
	}
}

// **どの絞り込みでも、表全体を読んで並べ替える計画にならない。**
//
// 監査ログは増え続ける(保持は無限)。v1 の索引 (at DESC) だけでは、操作や結果
// だけの絞り込みで SQLite が「表を全て読んでから並べ替える」計画を選ぶ。
// idx_audit_head は一覧の並び順どおりに、一覧が拾う行だけを持つ。**索引を
// 新しい順に辿り、1 ページ分が揃ったら止まる計画であること**を、実行計画で固定する。
// 「速いはず」ではなく、計画そのものを見る。索引は SQL で指定していない
// (SQLite が選ぶ)ので、索引や並び順を変えたときにここが落ちる。
func TestListAuditLogsNeverSortsTheWholeTable(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	id := int64(1)
	pos := &AuditCursor{At: vaultNow.Unix(), ID: 42}

	tests := []struct {
		name  string
		query AuditQuery
		index string
	}{
		{"no filter", AuditQuery{}, "idx_audit_head"},
		{"older page", AuditQuery{Before: pos}, "idx_audit_head"},
		{"newer page", AuditQuery{After: pos}, "idx_audit_head"},
		{"period", AuditQuery{Filter: AuditFilter{From: ptr(vaultNow), To: ptr(vaultNow.Add(time.Hour))}}, "idx_audit_head"},
		{"action only", AuditQuery{Filter: AuditFilter{Action: ActionSecretReveal}}, "idx_audit_head"},
		{"result only", AuditQuery{Filter: AuditFilter{Result: ResultFailure}}, "idx_audit_head"},
		{"action and page", AuditQuery{Filter: AuditFilter{Action: ActionAuthUser, Result: ResultFailure}, After: pos}, "idx_audit_head"},
		// machine と環境にも、一覧が拾う行だけを並び順どおりに持つ索引がある
		// (bulk fetch を調べるときに最も使う絞り込み)。
		{"actor machine", AuditQuery{Filter: AuditFilter{ActorMachineID: &id}, Before: pos}, "idx_audit_head_machine"},
		{"machine and action", AuditQuery{Filter: AuditFilter{ActorMachineID: &id, Action: ActionSecretRead}}, "idx_audit_head_machine"},
		{"environment", AuditQuery{Filter: AuditFilter{EnvironmentID: &id}}, "idx_audit_head_env"},
		// user と anonymous は v1 の索引で絞ってから時刻順に辿る(batch の後続行は
		// machine の行なので、ここには混ざらない)。
		{"anonymous", AuditQuery{Filter: AuditFilter{ActorAnonymous: true}}, "idx_audit_actor_"},
		{"actor user", AuditQuery{Filter: AuditFilter{ActorUserID: &id}}, "idx_audit_actor_user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.query.Limit = 100
			query, args := tt.query.listSQL()
			plan := queryPlan(t, db, query, args...)

			// 同じ秒の中を id で並べる部分的な並べ替え(LAST TERM)は、読んだ分に
			// しか掛からないのでよい。ORDER BY 全体の並べ替えは表全体を読む。
			if strings.Contains(plan, "USE TEMP B-TREE FOR ORDER BY") {
				t.Errorf("the plan sorts every matching row before returning a page:\n%s", plan)
			}
			if !strings.Contains(plan, " a USING INDEX "+tt.index) {
				t.Errorf("the plan does not walk audit_logs through %s*:\n%s", tt.index, plan)
			}
			// idx_audit_head* は並び順どおりなので、並べ替えが一切要らない。
			if strings.HasPrefix(tt.index, "idx_audit_head") && strings.Contains(plan, "USE TEMP B-TREE") {
				t.Errorf("the plan sorts although %s is already in list order:\n%s", tt.index, plan)
			}
		})
	}
}

// 「戻る」リンクの有無を確かめる問い合わせも、同じ索引で引く。
func TestAuditRowExistsUsesTheListIndex(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	for _, op := range []string{"<", ">"} {
		where, args := AuditFilter{Action: ActionSeal}.whereFrom(op, AuditCursor{At: vaultNow.Unix(), ID: 42})
		plan := queryPlan(t, db, `SELECT EXISTS(SELECT 1 FROM audit_logs a WHERE `+where+`)`, args...)
		if !strings.Contains(plan, "SEARCH a USING INDEX idx_audit_head") {
			t.Errorf("probe %q does not use idx_audit_head:\n%s", op, plan)
		}
	}
}

// 削除した environment も、絞り込みの選択肢に出る(過去のアクセスを調べるため)。
func TestListAuditEnvironmentsIncludesDeletedOnes(t *testing.T) {
	t.Parallel()

	db := newTestStore(t).DB()
	live := insertProject(t, db, "myapp", false)
	insertEnvironment(t, db, live, "prod", false)
	insertEnvironment(t, db, live, "old", true)
	gone := insertProject(t, db, "retired", true)
	insertEnvironment(t, db, gone, "prod", false)

	envs, err := ListAuditEnvironments(t.Context(), db)
	if err != nil {
		t.Fatalf("ListAuditEnvironments: %v", err)
	}
	var got []string
	for _, e := range envs {
		got = append(got, fmt.Sprintf("%s/%s deleted=%v", e.ProjectSlug, e.EnvSlug, e.Deleted))
	}
	// project が削除されていれば、配下の environment も削除済みとして扱う。
	want := []string{"myapp/old deleted=true", "myapp/prod deleted=false", "retired/prod deleted=true"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// ---- クエリ文字列 ----

func TestParseAuditQuery(t *testing.T) {
	t.Parallel()

	jst := time.FixedZone("JST", 9*60*60)

	t.Run("empty query is the newest page with the default size", func(t *testing.T) {
		t.Parallel()

		q, view, err := parseAuditQuery("", jst)
		if err != nil {
			t.Fatalf("parseAuditQuery: %v", err)
		}
		if q.Limit != auditDefaultPageSize || q.Before != nil || q.After != nil || q.Filter != (AuditFilter{}) {
			t.Errorf("query = %+v, want the zero filter and the default limit", q)
		}
		if view.Filtered() {
			t.Error("view.Filtered is set for an empty query")
		}
	})

	t.Run("every field", func(t *testing.T) {
		t.Parallel()

		v := url.Values{
			"from": {"2026-10-01"}, "to": {"2026-10-03"}, "actor": {"machine:7"},
			"action": {"secret.read"}, "result": {"failure"}, "env": {"12"},
			"n": {"50"}, "before": {"1700000000-42"},
		}
		q, view, err := parseAuditQuery(v.Encode(), jst)
		if err != nil {
			t.Fatalf("parseAuditQuery: %v", err)
		}
		// 日付はサーバーのローカル時刻で解釈し、終了日はその日を含める。
		if want := time.Date(2026, 10, 1, 0, 0, 0, 0, jst); !q.Filter.From.Equal(want) {
			t.Errorf("From = %v, want %v", q.Filter.From, want)
		}
		if want := time.Date(2026, 10, 4, 0, 0, 0, 0, jst); !q.Filter.To.Equal(want) {
			t.Errorf("To = %v, want %v (the end date is inclusive)", q.Filter.To, want)
		}
		if q.Filter.ActorMachineID == nil || *q.Filter.ActorMachineID != 7 || q.Filter.ActorUserID != nil || q.Filter.ActorAnonymous {
			t.Errorf("actor = %+v, want machine 7 only", q.Filter)
		}
		if q.Filter.Action != ActionSecretRead || q.Filter.Result != ResultFailure {
			t.Errorf("action/result = %q/%q", q.Filter.Action, q.Filter.Result)
		}
		if q.Filter.EnvironmentID == nil || *q.Filter.EnvironmentID != 12 {
			t.Errorf("env = %v, want 12", q.Filter.EnvironmentID)
		}
		if q.Limit != 50 || q.Before == nil || *q.Before != (AuditCursor{At: 1700000000, ID: 42}) || q.After != nil {
			t.Errorf("limit/before/after = %d/%v/%v", q.Limit, q.Before, q.After)
		}
		if !view.Filtered() {
			t.Error("view.Filtered is not set")
		}

		// **ページ送りの URL は、同じ絞り込みと件数を保つ。** 往復させて確かめる。
		next, err := url.Parse(view.pageURL("before", &AuditCursor{At: 1699999999, ID: 9}))
		if err != nil {
			t.Fatalf("parse page url: %v", err)
		}
		if next.Path != "/ui/audit" {
			t.Errorf("page url path = %q", next.Path)
		}
		q2, _, err := parseAuditQuery(next.RawQuery, jst)
		if err != nil {
			t.Fatalf("the generated page url does not parse: %v", err)
		}
		if *q2.Before != (AuditCursor{At: 1699999999, ID: 9}) || q2.Limit != q.Limit ||
			!q2.Filter.From.Equal(*q.Filter.From) || !q2.Filter.To.Equal(*q.Filter.To) ||
			*q2.Filter.ActorMachineID != 7 || q2.Filter.Action != q.Filter.Action ||
			q2.Filter.Result != q.Filter.Result || *q2.Filter.EnvironmentID != 12 {
			t.Errorf("round trip changed the query:\n got  %+v\n want %+v", q2, q)
		}
	})

	t.Run("actor forms", func(t *testing.T) {
		t.Parallel()

		q, _, err := parseAuditQuery("actor=anonymous", jst)
		if err != nil || !q.Filter.ActorAnonymous {
			t.Errorf("anonymous: filter %+v, err %v", q.Filter, err)
		}
		q, _, err = parseAuditQuery("actor=user%3A3", jst)
		if err != nil || q.Filter.ActorUserID == nil || *q.Filter.ActorUserID != 3 {
			t.Errorf("user:3: filter %+v, err %v", q.Filter, err)
		}
	})

	// **allowlist と型に落ちない値は全て拒否する。** 黙って無視すると、利用者は
	// 絞り込めているつもりで全件を見ることになる。
	invalid := map[string]url.Values{
		"date format":            {"from": {"2026/10/01"}},
		"date with time":         {"to": {"2026-10-01T00:00:00"}},
		"impossible date":        {"from": {"2026-02-30"}},
		"unknown action":         {"action": {"secret.steal"}},
		"action with sql":        {"action": {"secret.read' OR '1'='1"}},
		"unknown result":         {"result": {"maybe"}},
		"actor kind":             {"actor": {"robot:1"}},
		"actor without id":       {"actor": {"user"}},
		"actor zero":             {"actor": {"user:0"}},
		"actor negative":         {"actor": {"machine:-1"}},
		"actor not canonical":    {"actor": {"user:01"}},
		"actor with sign":        {"actor": {"user:+1"}},
		"actor trailing":         {"actor": {"user:1 "}},
		"env not a number":       {"env": {"prod"}},
		"env zero":               {"env": {"0"}},
		"env not canonical":      {"env": {"012"}},
		"cursor not canonical":   {"before": {"01700000000-42"}},
		"cursor id with sign":    {"after": {"1700000000-+42"}},
		"date not zero padded":   {"from": {"2026-10-1"}},
		"page size not offered":  {"n": {"37"}},
		"page size huge":         {"n": {"1000000"}},
		"page size not a number": {"n": {"all"}},
		"page size zero padded":  {"n": {"050"}},
		"page size with sign":    {"n": {"+50"}},
		"before and after":       {"before": {"1-1"}, "after": {"2-2"}},
		"cursor without id":      {"before": {"1700000000"}},
		"cursor not numbers":     {"after": {"a-b"}},
		"cursor negative time":   {"before": {"-5-1"}},
		"cursor zero id":         {"before": {"1700000000-0"}},
	}
	for name, v := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := parseAuditQuery(v.Encode(), jst); err == nil {
				t.Errorf("parseAuditQuery accepted %v", v)
			}
		})
	}
}

// **解釈できないクエリ文字列と、同じ名前が重なったクエリは拒否する。**
//
// http.Request.URL.Query() は解釈できなかった組を黙って捨てる。それを使うと
// `?action=secret.reveal%zz` が「絞り込みなし」として通り、利用者は絞り込めている
// つもりで全件を見ることになる。
func TestParseAuditQueryRejectsBrokenQueryStrings(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"broken percent escape":   "action=secret.reveal%zz",
		"semicolon separator":     "actor=machine:3;x=1",
		"duplicate filter":        "action=seal&action=logout",
		"duplicate page size":     "n=50&n=200",
		"duplicate with an empty": "env=&env=3",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := parseAuditQuery(raw, time.UTC); err == nil {
				t.Errorf("parseAuditQuery accepted %q", raw)
			}
		})
	}

	// フォームは空の項目も送る(?from=&to=&actor=...)。それは「指定なし」である。
	q, view, err := parseAuditQuery("from=&to=&actor=&action=&result=&env=&n=100", time.UTC)
	if err != nil {
		t.Fatalf("parseAuditQuery rejected the form's empty fields: %v", err)
	}
	if q.Filter != (AuditFilter{}) || view.Filtered() {
		t.Errorf("empty form fields produced a filter: %+v", q.Filter)
	}
}

// **key の多い batch は、一覧では途中までを出し、件数は実数を出す。**
// 全ての key は batch の画面で読める。
func TestListAuditLogsCapsTheKeysShownPerBatch(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	const total = auditBatchInlineLimit + 25
	keys := make([]string, total)
	for i := range keys {
		keys[i] = fmt.Sprintf("KEY_%03d", i)
	}
	if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", vaultNow.Add(time.Hour), keys...)); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	// 上限ちょうどの batch は省略しない。
	if err := recordBatch(t, s.db, s.readEntries(s.stagingID, "staging", vaultNow.Add(2*time.Hour), keys[:auditBatchInlineLimit]...)); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}

	page := mustList(t, s.db, AuditQuery{Filter: AuditFilter{Action: ActionSecretRead}})
	if len(page.Rows) != 2 {
		t.Fatalf("listed %d rows, want 2", len(page.Rows))
	}
	exact, large := page.Rows[0], page.Rows[1]
	if exact.BatchSize != auditBatchInlineLimit || len(exact.Batch) != auditBatchInlineLimit || exact.BatchHidden() != 0 {
		t.Errorf("batch at the limit: size %d, shown %d, hidden %d; want all %d shown",
			exact.BatchSize, len(exact.Batch), exact.BatchHidden(), auditBatchInlineLimit)
	}
	if large.BatchSize != total || len(large.Batch) != auditBatchInlineLimit || large.BatchHidden() != 25 {
		t.Errorf("large batch: size %d, shown %d, hidden %d; want size %d, %d shown, 25 hidden",
			large.BatchSize, len(large.Batch), large.BatchHidden(), total, auditBatchInlineLimit)
	}
	// 出すのは先頭から(書かれた順)。
	if got := large.Batch[auditBatchInlineLimit-1].Target; got != fmt.Sprintf("myapp/prod/KEY_%03d", auditBatchInlineLimit-1) {
		t.Errorf("last shown item = %q, want the first %d keys in order", got, auditBatchInlineLimit)
	}

	// batch の画面は 1 件も省略しない。
	full, err := ListAuditBatch(t.Context(), s.db, large.ID)
	if err != nil {
		t.Fatalf("ListAuditBatch: %v", err)
	}
	if full.BatchSize != total || len(full.Batch) != total || full.BatchHidden() != 0 {
		t.Errorf("batch page: size %d, shown %d; want all %d", full.BatchSize, len(full.Batch), total)
	}
	if got := full.Batch[total-1].Target; got != fmt.Sprintf("myapp/prod/KEY_%03d", total-1) {
		t.Errorf("last item on the batch page = %q", got)
	}
	if full.Target != large.Target || full.Actor != large.Actor {
		t.Errorf("batch page head = %q / %q, want the same as the list row %q / %q", full.Actor, full.Target, large.Actor, large.Target)
	}
}

// batch の先頭行でない id は、batch の画面に出さない。
func TestListAuditBatchRejectsNonHeadRows(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", vaultNow.Add(time.Hour), "A", "B", "C")); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	mustRecord(t, s.db, s.readEntries(s.prodID, "prod", vaultNow.Add(2*time.Hour), "D")...)

	rows := auditBatchRows(t, s.db, ActionSecretRead)
	head, member, single := rows[0].ID, rows[1].ID, rows[3].ID

	if _, err := ListAuditBatch(t.Context(), s.db, head); err != nil {
		t.Errorf("head row: %v", err)
	}
	for name, id := range map[string]int64{"a later row of the batch": member, "a single row": single, "a missing row": 99999} {
		if _, err := ListAuditBatch(t.Context(), s.db, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
}

// **batch の対象列は、記録時点の文字列から作る。**
//
// audit_logs は FK を持たず、参照先が引けない行も表示する。現在の slug を JOIN で
// 引く形だと、environment の行が引けない batch では、どの環境の読み取りかが
// 畳んだ行から読めなくなる。
func TestListAuditLogsBatchTargetDoesNotDependOnTheJoin(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	missingEnv := int64(99999)
	if err := recordBatch(t, s.db, s.readEntries(missingEnv, "gone", vaultNow.Add(time.Hour), "A", "B")); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}

	page := mustList(t, s.db, AuditQuery{Filter: AuditFilter{Action: ActionSecretRead}})
	if len(page.Rows) != 1 {
		t.Fatalf("listed %d rows, want 1", len(page.Rows))
	}
	if page.Rows[0].Target != "myapp/gone" {
		t.Errorf("batch target = %q, want %q", page.Rows[0].Target, "myapp/gone")
	}
}

// 最新のページを指す URL は、既定の件数や空の条件を持ち回らない。
func TestAuditPageURLOmitsDefaults(t *testing.T) {
	t.Parallel()

	_, view, err := parseAuditQuery("n=100", time.UTC)
	if err != nil {
		t.Fatalf("parseAuditQuery: %v", err)
	}
	if got := view.pageURL("", nil); got != "/ui/audit" {
		t.Errorf("pageURL = %q, want /ui/audit", got)
	}
	if got := view.pageURL("before", &AuditCursor{At: 5, ID: 6}); got != "/ui/audit?before=5-6" {
		t.Errorf("pageURL = %q, want /ui/audit?before=5-6", got)
	}
}

// ---- 画面 ----

// **bulk fetch は画面で 1 行にまとまり、開くと key が全て読める。**
// 部品(ListAuditLogs)が正しくても、ハンドラとテンプレートが繋がっていなければ
// 意味がないので、HTTP で叩いて確かめる。
func TestUIAuditPageFoldsABulkFetch(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)
	machineID, _, err := CreateMachine(t.Context(), f.store.DB(), "app-prod", "web01", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}

	ac := machineAudit(machineID, "10.0.0.2", vaultNow)
	var entries []AuditEntry
	for _, key := range []string{"API_TOKEN", "DATABASE_URL", "SMTP_PASSWORD"} {
		target := env.ProjectSlug + "/" + env.EnvSlug + "/" + key
		entry := ac.entry(ActionSecretRead, ResultSuccess, nil)
		entry.Target = &target
		entry.TargetEnvironmentID = &env.EnvironmentID
		entries = append(entries, entry)
	}
	if err := recordBatch(t, f.store.DB(), entries); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}

	w := f.get(t, "/ui/audit?action=secret.read")
	if w.Code != http.StatusOK {
		t.Fatalf("audit page = %d", w.Code)
	}
	body := w.Body.String()
	if got := strings.Count(body, `<tr class="success">`); got != 1 {
		t.Errorf("the page has %d rows, want the bulk fetch as 1", got)
	}
	if !strings.Contains(body, "<summary>3 件の key</summary>") {
		t.Error("the page does not show the number of keys in the batch")
	}
	for _, key := range []string{"API_TOKEN", "DATABASE_URL", "SMTP_PASSWORD"} {
		if want := env.ProjectSlug + "/" + env.EnvSlug + "/" + key; !strings.Contains(body, want) {
			t.Errorf("the page does not list %s inside the batch", want)
		}
	}
	// 選んだ条件がフォームに戻る。
	if !strings.Contains(body, `<option value="secret.read" selected>`) {
		t.Error("the action filter is not shown as selected")
	}
	if !strings.Contains(body, `href="/ui/audit">解除</a>`) {
		t.Error("the page has no link to clear the filter")
	}
}

// 絞り込みに合わない行は出ない。ページ送りのリンクは絞り込みを保つ。
func TestUIAuditPageFiltersAndPages(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	for i := range 60 {
		ac := f.auditCtx()
		ac.Now = vaultNow.Add(time.Duration(i) * time.Second)
		if err := RecordAudit(t.Context(), f.store.DB(), ac.entry(ActionLogout, ResultSuccess, nil)); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
	f.seedSecret(t, "DATABASE_URL", testSecretValue) // secret.write が 1 行入る

	w := f.get(t, "/ui/audit?action=logout&n=50")
	if w.Code != http.StatusOK {
		t.Fatalf("audit page = %d", w.Code)
	}
	body := w.Body.String()
	if got := strings.Count(body, `<td class="key">logout</td>`); got != 50 {
		t.Errorf("the page lists %d logout rows, want 50", got)
	}
	if strings.Contains(body, `<td class="key">secret.write</td>`) {
		t.Error("a row that does not match the filter is listed")
	}
	if strings.Contains(body, "新しい方へ") || strings.Contains(body, "最新へ") {
		t.Error("the newest page links to newer rows")
	}

	// 「古い方へ」のリンクを辿ると、残りの 10 件が出る。
	_, rest, found := strings.Cut(body, `<a href="/ui/audit?`)
	if !found {
		t.Fatal("the page has no link to older rows")
	}
	query, _, _ := strings.Cut(rest, `"`)
	href := "/ui/audit?" + strings.ReplaceAll(query, "&amp;", "&")
	if !strings.Contains(href, "action=logout") || !strings.Contains(href, "n=50") || !strings.Contains(href, "before=") {
		t.Fatalf("the older link %q does not keep the filter and the page size", href)
	}

	body = f.get(t, href).Body.String()
	if got := strings.Count(body, `<td class="key">logout</td>`); got != 10 {
		t.Errorf("the second page lists %d logout rows, want 10", got)
	}
	if strings.Contains(body, "古い方へ") {
		t.Error("the last page links to older rows")
	}
	if !strings.Contains(body, "新しい方へ") || !strings.Contains(body, "最新へ") {
		t.Error("the second page has no way back to newer rows")
	}
}

// **不正なクエリ文字列は 400 で、入力を画面に戻さない。**
//
// 値はフォームの選択状態として画面に戻るので、検証を通らない値をそのまま
// 戻すと、URL を踏ませるだけで他人の画面に文字列を出せる。
func TestUIAuditPageRejectsInvalidQueries(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	const payload = `"><script>alert(1)</script>`
	for _, param := range []string{"action", "actor", "result", "env", "from", "to", "n", "before", "after"} {
		w := f.get(t, "/ui/audit?"+url.Values{param: {payload}}.Encode())
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s=%q: status = %d, want 400", param, payload, w.Code)
		}
		if body := w.Body.String(); strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "alert(1)") {
			t.Errorf("%s: the rejected value is reflected in the page", param)
		}
	}
}

// **「詳細」の列は無く、key と detail は対象の中に畳まれる。**
//
// 1 件だけの読み取りも「1 件の key」として畳み、key を対象にしない行の detail
// (失敗の理由など)は「詳細」として畳む。detail を捨ててはならない
// (失敗の理由は、探索行為と設定ミスを見分ける手掛かりである)。
func TestUIAuditPageFoldsKeysAndDetails(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue) // secret.write が 1 行入る
	reason := ReasonInvalidCredentials
	failed := auditCtx{Actor: ActorAnonymous, Via: ViaWeb, Now: vaultNow}.
		entry(ActionAuthUser, ResultFailure, &AuditDetail{Reason: &reason})
	if err := RecordAudit(t.Context(), f.store.DB(), failed); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	body := f.get(t, "/ui/audit").Body.String()
	if strings.Contains(body, "<th>詳細</th>") {
		t.Error("the table still has a 詳細 column")
	}
	if got := strings.Count(body, "<th>"); got != 6 {
		t.Errorf("the table has %d columns, want 6", got)
	}

	// key の行: 対象列は project/env、key と detail は畳んだ中。
	key := env.ProjectSlug + "/" + env.EnvSlug + "/DATABASE_URL"
	if !strings.Contains(body, "<summary>1 件の key</summary>") {
		t.Error("a single key is not folded as 「1 件の key」")
	}
	if !strings.Contains(body, `<li><span class="key">`+key+`</span> <span class="detail">{&#34;version&#34;:1`) {
		t.Errorf("the folded item does not carry the key %s and its detail", key)
	}
	if !strings.Contains(body, "<td>"+env.ProjectSlug+"/"+env.EnvSlug+"\n") {
		t.Errorf("the target column does not show %s/%s on its own", env.ProjectSlug, env.EnvSlug)
	}

	// key の無い行: detail は「詳細」として畳む。
	if !strings.Contains(body, "<summary>詳細</summary>") {
		t.Error("the detail of a row without a key is not folded as 「詳細」")
	}
	if !strings.Contains(body, `&#34;reason&#34;:&#34;invalid_credentials&#34;`) {
		t.Error("the failure reason is no longer on the page")
	}
}

// key の多い batch は、一覧で省略を明示し、全件を出す画面へ繋がる。
func TestUIAuditBatchPage(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)
	machineID, _, err := CreateMachine(t.Context(), f.store.DB(), "app-prod", "web01", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}

	const total = auditBatchInlineLimit + 3
	ac := machineAudit(machineID, "10.0.0.2", vaultNow)
	entries := make([]AuditEntry, 0, total)
	for i := range total {
		target := fmt.Sprintf("%s/%s/KEY_%03d", env.ProjectSlug, env.EnvSlug, i)
		entry := ac.entry(ActionSecretRead, ResultSuccess, nil)
		entry.Target = &target
		entry.TargetEnvironmentID = &env.EnvironmentID
		entries = append(entries, entry)
	}
	if err := recordBatch(t, f.store.DB(), entries); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	headID := auditBatchRows(t, f.store.DB(), ActionSecretRead)[0].ID
	lastKey := fmt.Sprintf("KEY_%03d", total-1)

	list := f.get(t, "/ui/audit?action=secret.read").Body.String()
	if !strings.Contains(list, fmt.Sprintf("<summary>%d 件の key</summary>", total)) {
		t.Errorf("the list does not show the real number of keys (%d)", total)
	}
	link := fmt.Sprintf(`他 3 件は省略しています。<a href="/ui/audit/batch/%d">全て表示</a>`, headID)
	if !strings.Contains(list, link) {
		t.Errorf("the list does not say that keys are omitted or link to the batch page; want %q", link)
	}
	if strings.Contains(list, lastKey) {
		t.Errorf("the list shows %s, which is beyond the inline limit", lastKey)
	}

	w := f.get(t, fmt.Sprintf("/ui/audit/batch/%d", headID))
	if w.Code != http.StatusOK {
		t.Fatalf("batch page = %d", w.Code)
	}
	body := w.Body.String()
	if got := strings.Count(body, `<td class="key">`+env.ProjectSlug+"/"+env.EnvSlug+"/KEY_"); got != total {
		t.Errorf("the batch page lists %d keys, want all %d", got, total)
	}
	if !strings.Contains(body, lastKey) {
		t.Errorf("the batch page does not list %s", lastKey)
	}

	// 先頭行でない id、存在しない id、数でない id。
	for path, want := range map[string]int{
		fmt.Sprintf("/ui/audit/batch/%d", headID+1): http.StatusNotFound,
		"/ui/audit/batch/999999":                    http.StatusNotFound,
		"/ui/audit/batch/abc":                       http.StatusBadRequest,
		"/ui/audit/batch/0":                         http.StatusBadRequest,
	} {
		if got := f.get(t, path).Code; got != want {
			t.Errorf("GET %s = %d, want %d", path, got, want)
		}
	}
}

// batch の画面も、認証と unseal を要求する(他の監査の画面と同じ)。
func TestUIAuditBatchPageRequiresASession(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	w := f.do(t, http.MethodGet, "/ui/audit/batch/1", nil, false)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Errorf("without a session: status = %d, want a redirect to the login page", w.Code)
	}
}

// 絞り込みの選択肢に、実行者(user / machine / anonymous)と environment が並ぶ。
// 無効化した machine と削除した environment も選べる。
func TestUIAuditPageOffersFilterOptions(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)
	machineID, _, err := CreateMachine(t.Context(), f.store.DB(), "app-old", "旧バッチ", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	if _, err := f.store.DB().ExecContext(t.Context(), `UPDATE machines SET disabled = 1 WHERE id = ?`, machineID); err != nil {
		t.Fatalf("disable machine: %v", err)
	}
	if _, err := f.store.DB().ExecContext(t.Context(),
		`UPDATE environments SET deleted_at = ? WHERE id = ?`, vaultNow.Unix(), env.EnvironmentID); err != nil {
		t.Fatalf("delete environment: %v", err)
	}

	body := f.get(t, "/ui/audit").Body.String()
	for _, want := range []string{
		fmt.Sprintf(`<option value="user:%d">%s (user:%d)</option>`, f.userID, testUsername, f.userID),
		fmt.Sprintf(`<option value="machine:%d">旧バッチ (machine:%d)</option>`, machineID, machineID),
		`<option value="anonymous">anonymous</option>`,
		fmt.Sprintf(`<option value="%d">%s/%s(削除済み)</option>`, env.EnvironmentID, env.ProjectSlug, env.EnvSlug),
		`<option value="secret.read">secret.read</option>`,
		`<option value="100" selected>100</option>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the audit page does not offer %q", want)
		}
	}
}

// ---- 別の目で足したテスト(ページ送りと batch の噛み合わせ) ----

// headIDsNewestFirst は、一覧に出るはずの行(batch_id の無い行)の id を新しい順に
// 返す。**ListAuditLogs を通さずに DB から直接作る**(期待値を被検査の関数で作らない)。
// at が id と同じ向きに増えるように行を書いたテストでだけ使える。
func headIDsNewestFirst(t *testing.T, db *sql.DB) (heads []int64, members map[int64]bool) {
	t.Helper()

	members = map[int64]bool{}
	for _, r := range auditBatchRows(t, db, "") {
		if r.Batch.Valid {
			members[r.ID] = true
			continue
		}
		heads = append(heads, r.ID)
	}
	slices.Reverse(heads)
	return heads, members
}

// **batch と単独の行が同じ秒に混ざっていても、ページを歩くと先頭行だけが
// ちょうど 1 回ずつ出る。** 後続行は、どのページにも単独の行として出ない。
//
// batch の後続行は先頭行と同じ at を持ち、id は先頭行の直後に続く。位置
// (at, id)の比較に後続行が混ざると、ページの境界で後続行が拾われるか、
// 境界の次の先頭行が飛ぶ。
func TestListAuditLogsPagesAcrossBatchesAndTies(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	for i := range 14 {
		// 5 行ごとに 1 秒進む。同じ秒の中に batch と単独の行が交互に並ぶ。
		at := vaultNow.Add(time.Duration(i/5+1) * time.Second)
		if i%2 == 0 {
			if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", at, "A", "B", "C")); err != nil {
				t.Fatalf("RecordAuditBatch: %v", err)
			}
			continue
		}
		mustRecord(t, s.db, s.userAudit(at).entry(ActionLogout, ResultSuccess, nil))
	}
	want, members := headIDsNewestFirst(t, s.db)
	if len(want) != 15 || len(members) != 14 {
		t.Fatalf("test setup: %d head rows and %d later rows, want 15 and 14", len(want), len(members))
	}

	check := func(page AuditPage) {
		t.Helper()
		for _, r := range page.Rows {
			if members[r.ID] {
				t.Errorf("row %d is a later row of a batch but is listed on its own", r.ID)
			}
			if r.Action == string(ActionSecretRead) && (r.BatchSize != 3 || len(r.Batch) != 3) {
				t.Errorf("batch %d: size %d, %d items; want 3 and 3 on every page", r.ID, r.BatchSize, len(r.Batch))
			}
			if r.Action != string(ActionSecretRead) && (r.BatchSize != 0 || len(r.Batch) != 0) {
				t.Errorf("single row %d (%s) has batch items", r.ID, r.Action)
			}
		}
	}

	const size = 3
	var walked []int64
	page := mustList(t, s.db, AuditQuery{Limit: size})
	for {
		check(page)
		walked = append(walked, rowIDs(page.Rows)...)
		if page.Older == nil {
			break
		}
		page = mustList(t, s.db, AuditQuery{Limit: size, Before: page.Older})
	}
	if !slices.Equal(walked, want) {
		t.Errorf("walking older:\n got  %v\n want %v", walked, want)
	}

	var back []int64
	for {
		check(page)
		back = append(slices.Clone(rowIDs(page.Rows)), back...)
		if page.Newer == nil {
			break
		}
		page = mustList(t, s.db, AuditQuery{Limit: size, After: page.Newer})
	}
	if !slices.Equal(back, want) {
		t.Errorf("walking newer:\n got  %v\n want %v", back, want)
	}
}

// **ページを読んでいる間に行が足されても、次のページはずれない**(keyset)。
//
// OFFSET で数える実装だと、1 ページ目を読んだ後に 3 行足されると、2 ページ目の
// 先頭に 1 ページ目の末尾 3 行がもう一度出る。監査ログは読んでいる間も増える。
func TestListAuditLogsPagingIsStableWhenRowsAreAdded(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	for i := range 9 {
		mustRecord(t, s.db, s.userAudit(vaultNow.Add(time.Duration(i+1)*time.Second)).entry(ActionLogout, ResultSuccess, nil))
	}
	before, _ := headIDsNewestFirst(t, s.db) // 10 行(seed の machine.create を含む)

	const size = 4
	first := mustList(t, s.db, AuditQuery{Limit: size})
	if !slices.Equal(rowIDs(first.Rows), before[:size]) {
		t.Fatalf("first page = %v, want %v", rowIDs(first.Rows), before[:size])
	}

	// 1 ページ目を読んだ後に、新しい行(単独 2 行と batch 1 つ)が足される。
	later := vaultNow.Add(time.Hour)
	mustRecord(t, s.db, s.userAudit(later).entry(ActionAuthUser, ResultSuccess, nil))
	if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", later, "A", "B")); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	mustRecord(t, s.db, s.userAudit(later).entry(ActionAuthUser, ResultSuccess, nil))
	after, _ := headIDsNewestFirst(t, s.db)
	added := after[:len(after)-len(before)]
	if len(added) != 3 {
		t.Fatalf("test setup: %d head rows were added, want 3", len(added))
	}

	second := mustList(t, s.db, AuditQuery{Limit: size, Before: first.Older})
	if got, want := rowIDs(second.Rows), before[size:2*size]; !slices.Equal(got, want) {
		t.Errorf("second page after rows were added = %v, want %v (no row repeated, none skipped)", got, want)
	}

	// 足された行は、1 ページ目の先頭から新しい方へ進むと出る。
	top := &AuditCursor{At: first.Rows[0].At.Unix(), ID: first.Rows[0].ID}
	newer := mustList(t, s.db, AuditQuery{Limit: size, After: top})
	if got := rowIDs(newer.Rows); !slices.Equal(got, added) {
		t.Errorf("rows newer than the first page = %v, want the added rows %v", got, added)
	}
	if newer.Newer != nil {
		t.Error("the page of added rows links to even newer rows")
	}
	if newer.Older == nil || *newer.Older != (AuditCursor{At: later.Unix(), ID: added[len(added)-1]}) {
		t.Errorf("the page of added rows: Older = %v, want the position of its oldest row", newer.Older)
	}
}

// **絞り込みの下で、両端のリンクは「条件に合う行」があるときだけ出る。**
//
// 条件に合わない行が、合う行より古い側にも新しい側にもある状態で歩く。
// 逆方向の有無を条件なしで確かめる実装だと、端のページに行き先の無いリンクが出る。
// 新しい方へ進んだ先が 1 ページに満たないときも、新しい順で返す。
func TestListAuditLogsEndsOfAFilteredList(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	var logouts []int64 // 古い順
	for i := range 9 {
		action := ActionLogout
		if i == 0 || i == 8 {
			action = ActionAuthUser // 条件に合わない行を両端に置く
		}
		mustRecord(t, s.db, s.userAudit(vaultNow.Add(time.Duration(i+1)*time.Minute)).entry(action, ResultSuccess, nil))
	}
	for _, r := range auditBatchRows(t, s.db, ActionLogout) {
		logouts = append(logouts, r.ID)
	}
	if len(logouts) != 7 {
		t.Fatalf("test setup: %d logout rows, want 7", len(logouts))
	}
	// newest(i) は新しい方から数えて i 番目(0 始まり)の logout の id。
	newest := func(idx ...int) []int64 {
		out := make([]int64, len(idx))
		for i, n := range idx {
			out[i] = logouts[len(logouts)-1-n]
		}
		return out
	}

	filter := AuditFilter{Action: ActionLogout}
	const size = 3
	expect := func(name string, page AuditPage, want []int64, older, newer bool) {
		t.Helper()
		if got := rowIDs(page.Rows); !slices.Equal(got, want) {
			t.Errorf("%s: rows = %v, want %v", name, got, want)
		}
		if (page.Older != nil) != older || (page.Newer != nil) != newer {
			t.Errorf("%s: older link %v, newer link %v; want %v and %v", name, page.Older != nil, page.Newer != nil, older, newer)
		}
	}

	p1 := mustList(t, s.db, AuditQuery{Filter: filter, Limit: size})
	expect("newest page", p1, newest(0, 1, 2), true, false)
	p2 := mustList(t, s.db, AuditQuery{Filter: filter, Limit: size, Before: p1.Older})
	expect("middle page", p2, newest(3, 4, 5), true, true)
	p3 := mustList(t, s.db, AuditQuery{Filter: filter, Limit: size, Before: p2.Older})
	// これより古い行は auth.user と machine.create だけなので、古い方へのリンクは出ない。
	expect("oldest page", p3, newest(6), false, true)
	if t.Failed() {
		t.FailNow() // 以降は上のリンクを使う
	}

	back2 := mustList(t, s.db, AuditQuery{Filter: filter, Limit: size, After: p3.Newer})
	expect("back to the middle", back2, newest(3, 4, 5), true, true)
	back1 := mustList(t, s.db, AuditQuery{Filter: filter, Limit: size, After: back2.Newer})
	// これより新しい行は auth.user だけなので、新しい方へのリンクは出ない。
	expect("back to the newest", back1, newest(0, 1, 2), true, false)

	// 新しい側に 1 ページ分の行が無い位置から進む。
	rows := mustList(t, s.db, AuditQuery{Filter: filter, Limit: 100}).Rows
	pos := &AuditCursor{At: rows[2].At.Unix(), ID: rows[2].ID}
	short := mustList(t, s.db, AuditQuery{Filter: filter, Limit: size, After: pos})
	expect("short newer page", short, newest(0, 1), true, false)
}

// **期間の境界を、クエリ文字列から問い合わせまで通して確かめる。**
//
// 開始日はその日の 0 時を含み、終了日はその日の最後の 1 秒まで含む。日付は
// 渡した場所の時刻で解釈する(UTC で切ると、JST の画面で見える日付と 9 時間ずれる)。
func TestAuditPeriodBoundariesEndToEnd(t *testing.T) {
	t.Parallel()

	jst := time.FixedZone("JST", 9*60*60)
	s := newAuditSeed(t) // seed の行は 2023 年で、どの期間にも入らない
	for _, at := range []time.Time{
		time.Date(2026, 9, 30, 23, 59, 59, 0, jst),
		time.Date(2026, 10, 1, 0, 0, 0, 0, jst),
		time.Date(2026, 10, 3, 23, 59, 59, 0, jst),
		time.Date(2026, 10, 4, 0, 0, 0, 0, jst),
	} {
		mustRecord(t, s.db, s.userAudit(at).entry(ActionLogout, ResultSuccess, nil))
	}

	tests := []struct {
		name  string
		query string
		loc   *time.Location
		want  []string // JST の時刻、新しい順
	}{
		{"from is inclusive, to covers its whole day", "from=2026-10-01&to=2026-10-03", jst,
			[]string{"10-03 23:59:59", "10-01 00:00:00"}},
		{"from only", "from=2026-10-04", jst, []string{"10-04 00:00:00"}},
		{"to only", "to=2026-09-30&action=logout", jst, []string{"09-30 23:59:59"}},
		{"a single day", "from=2026-10-01&to=2026-10-01", jst, []string{"10-01 00:00:00"}},
		// 同じ日付でも、場所が違えば別の 24 時間を指す。
		{"the same dates in UTC", "from=2026-10-01&to=2026-10-03", time.UTC,
			[]string{"10-04 00:00:00", "10-03 23:59:59"}},
		// 開始日が終了日より後なら、エラーではなく「該当なし」。
		{"from later than to", "from=2026-10-03&to=2026-10-01", jst, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			q, view, err := parseAuditQuery(tt.query, tt.loc)
			if err != nil {
				t.Fatalf("parseAuditQuery(%q): %v", tt.query, err)
			}
			if !view.Filtered() {
				t.Error("view.Filtered is not set for a period")
			}
			page := mustList(t, s.db, q)
			var got []string
			for _, r := range page.Rows {
				got = append(got, r.At.In(jst).Format("01-02 15:04:05"))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
			if page.Older != nil || page.Newer != nil {
				t.Errorf("older %v / newer %v, want no links (rows outside the period are not pages)", page.Older, page.Newer)
			}
		})
	}
}

// **終了日を指定したのに、絞り込みが黙って外れることがない。**
//
// AuditFilter は「ゼロ値の time.Time なら絞り込まない」と読む。終了日は翌日の
// 0 時に直すので、UTC で `to=0000-12-31` を渡すと 0001-01-01T00:00:00Z、つまり
// time.Time のゼロ値になる。拒否するか、絞り込んだまま(該当なし)にするかの
// どちらかでなければ、利用者は絞り込めているつもりで全件を見ることになる
// (parseAuditQuery が「1 つでも不正なら全体を拒否する」理由と同じ)。
func TestParseAuditQueryDoesNotDropAnEarlyEndDate(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	mustRecord(t, s.db, s.userAudit(vaultNow.Add(time.Hour)).entry(ActionLogout, ResultSuccess, nil))

	q, view, err := parseAuditQuery("to=0000-12-31", time.UTC)
	if err != nil {
		return // 拒否するなら、それでよい
	}
	if !view.Filtered() {
		t.Error("view.Filtered is not set although an end date was given")
	}
	if rows := mustList(t, s.db, q).Rows; len(rows) != 0 {
		t.Errorf("to=0000-12-31 was accepted but lists %d rows (Filter.To = %v); want no rows or a rejected query",
			len(rows), q.Filter.To)
	}
}

// 無効化した machine と、削除した environment / project でも絞り込める。
// 監査は過去の記録であり、いま使えないものほど調べる理由がある。
func TestListAuditLogsFiltersByDisabledAndDeletedTargets(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	at := vaultNow.Add(time.Hour)
	if err := recordBatch(t, s.db, s.readEntries(s.prodID, "prod", at, "A", "B")); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	mustRecord(t, s.db, s.readEntries(s.stagingID, "staging", at.Add(time.Second), "C")...)

	for _, stmt := range []string{
		`UPDATE machines SET disabled = 1`,
		`UPDATE environments SET deleted_at = 1700000000`,
		`UPDATE projects SET deleted_at = 1700000000`,
	} {
		if _, err := s.db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	byMachine := mustList(t, s.db, AuditQuery{Filter: AuditFilter{ActorMachineID: &s.machineID}})
	if len(byMachine.Rows) != 2 {
		t.Fatalf("filtering by a disabled machine lists %d rows, want 2", len(byMachine.Rows))
	}
	// 名前は現在の値を引く。無効化しても行は残るので、名前も出る。
	if want := fmt.Sprintf("web01 (machine:%d)", s.machineID); byMachine.Rows[0].Actor != want {
		t.Errorf("actor = %q, want %q", byMachine.Rows[0].Actor, want)
	}

	byEnv := mustList(t, s.db, AuditQuery{Filter: AuditFilter{EnvironmentID: &s.prodID}})
	if len(byEnv.Rows) != 1 || byEnv.Rows[0].BatchSize != 2 {
		t.Fatalf("filtering by a deleted environment: %d rows, want the batch of 2 as 1 row", len(byEnv.Rows))
	}
	if byEnv.Rows[0].Target != "myapp/prod" {
		t.Errorf("target = %q, want %q", byEnv.Rows[0].Target, "myapp/prod")
	}
	if _, err := ListAuditBatch(t.Context(), s.db, byEnv.Rows[0].ID); err != nil {
		t.Errorf("ListAuditBatch for a deleted environment: %v", err)
	}
}

// ---- クエリ文字列(追加) ----

// **知らない名前のパラメータは無視する。ただし、同じ名前が重なっていれば拒否する。**
//
// 知らない名前は絞り込みに関わらないので、付いていても結果は変わらない(外から
// 付く追跡用のパラメータなど)。重複と壊れた組は、名前を問わずクエリ全体を拒否する。
// この挙動を変えるなら意図して変えること。
func TestParseAuditQueryUnknownParameters(t *testing.T) {
	t.Parallel()

	q, view, err := parseAuditQuery("x=1&action=logout&utm_source=mail", time.UTC)
	if err != nil {
		t.Fatalf("parseAuditQuery rejected an unknown parameter name: %v", err)
	}
	if q.Filter != (AuditFilter{Action: ActionLogout}) {
		t.Errorf("filter = %+v, want only the action", q.Filter)
	}
	// 知らない名前は、ページ送りの URL に持ち回らない。
	if got := view.pageURL("", nil); got != "/ui/audit?action=logout" {
		t.Errorf("pageURL = %q, want /ui/audit?action=logout", got)
	}

	q, view, err = parseAuditQuery("x=secret.reveal", time.UTC)
	if err != nil {
		t.Fatalf("parseAuditQuery: %v", err)
	}
	if q.Filter != (AuditFilter{}) || view.Filtered() {
		t.Errorf("an unknown parameter produced a filter: %+v", q.Filter)
	}

	for _, raw := range []string{"x=1&x=2", "action=logout&x=1&x=1", "action=logout&x=%zz"} {
		if _, _, err := parseAuditQuery(raw, time.UTC); !errors.Is(err, errAuditQuery) {
			t.Errorf("parseAuditQuery(%q): err = %v, want errAuditQuery", raw, err)
		}
	}
}

// **正しい値と不正な値が混ざっていたら、全体を拒否する**(正しい方だけを採らない)。
// 併せて、既存の表に無い形の不正な値を足す。
func TestParseAuditQueryRejectsMixedAndMalformedValues(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		// 正しい値 + 不正な値。不正な値が先でも後でも同じ。
		"action=logout&env=abc",
		"env=abc&action=logout",
		"from=2026-10-01&to=2026-10-03&actor=machine%3A7&action=secret.read&result=success&env=12&n=50&before=1-x",
		"actor=anonymous&n=7",
		"result=success&from=2026-13-01",
		// actor
		"actor=anonymous%3A1",
		"actor=Anonymous",
		"actor=USER%3A1",
		"actor=user%3A1%3A2",
		"actor=machine%3A",
		"actor=%3A1",
		"actor=user%3A9223372036854775808",
		// 大文字小文字は区別する(allowlist の値そのものだけ)
		"action=SECRET.READ",
		"action=logout%00",
		"result=Success",
		// 位置
		"before=5-6-7",
		"before=5-",
		"before=-6",
		"after=9223372036854775808-1",
		"after=1.5-1",
		"after=1-1%20",
		// 日付と ID の前後の空白(+ は空白に復号される)
		"from=+2026-10-01",
		"to=2026-10-01+",
		"env=+3",
		"env=9223372036854775808",
		"env=1e3",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			if _, _, err := parseAuditQuery(raw, time.UTC); !errors.Is(err, errAuditQuery) {
				t.Errorf("parseAuditQuery(%q): err = %v, want errAuditQuery", raw, err)
			}
		})
	}

	// 片方が空の before / after は「指定なし」で、もう片方だけが効く。
	q, _, err := parseAuditQuery("before=&after=5-6", time.UTC)
	if err != nil || q.Before != nil || q.After == nil || *q.After != (AuditCursor{At: 5, ID: 6}) {
		t.Errorf("before=&after=5-6: before %v, after %v, err %v", q.Before, q.After, err)
	}
}

// **エラーは入力の値を含まない**(運用ログに出るため。ルール 25 と同じ理由)。
func TestParseAuditQueryErrorsDoNotEchoTheInput(t *testing.T) {
	t.Parallel()

	const marker = "zzmarkerzz"
	for _, param := range []string{"from", "to", "actor", "action", "result", "env", "n", "before", "after"} {
		_, _, err := parseAuditQuery(url.Values{param: {marker}}.Encode(), time.UTC)
		if err == nil {
			t.Errorf("%s=%s was accepted", param, marker)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the error %q contains the rejected value", param, err)
		}
	}
	// actor と位置は、区切りの後ろの数だけが不正な形もある(strconv のエラーは入力を含む)。
	for _, raw := range []string{"actor=user%3A" + marker, "before=5-" + marker, "after=" + marker + "-5", marker + "=%zz"} {
		if _, _, err := parseAuditQuery(raw, time.UTC); err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("parseAuditQuery(%q): err = %v, want an error without the input", raw, err)
		}
	}
}

// ---- 画面(追加) ----

var auditPagerLinkRE = regexp.MustCompile(`<a href="([^"]*)">([^<]*)</a>`)

// auditPagerLinks は、ページ送り(<nav class="pager">)のリンクを「表示 → href」で
// 返す。href は HTML の属性値から復元した、ブラウザが辿る URL である。
// ページ送りは表の上下に 2 つ出る。**両方が同じであること**もここで見る。
func auditPagerLinks(t *testing.T, body string) map[string]string {
	t.Helper()

	var navs []map[string]string
	for _, part := range strings.Split(body, `<nav class="pager">`)[1:] {
		nav, _, found := strings.Cut(part, "</nav>")
		if !found {
			t.Fatal("unterminated pager")
		}
		links := map[string]string{}
		for _, m := range auditPagerLinkRE.FindAllStringSubmatch(nav, -1) {
			links[strings.Trim(m[2], "←→ ")] = html.UnescapeString(m[1])
		}
		navs = append(navs, links)
	}
	if len(navs) == 0 {
		return nil
	}
	if len(navs) != 2 {
		t.Fatalf("the page has %d pagers, want 2 (above and below the table)", len(navs))
	}
	if fmt.Sprint(navs[0]) != fmt.Sprint(navs[1]) {
		t.Errorf("the two pagers differ:\n top    %v\n bottom %v", navs[0], navs[1])
	}
	return navs[0]
}

// **全ての絞り込みを指定した状態で、ページ送りのリンクを実際に辿る。**
//
// リンクは絞り込みと件数を保ち、解釈し直すと元と同じ問い合わせになる
// (actor の ':' のように、URL でエスケープされる値を含む)。古い方 → 新しい方 →
// 最新へ、の順に辿って、行数とフォームの選択状態を確かめる。
// 日付は、どの場所の時刻で解釈しても全ての行を含む範囲にする(handleAudit は
// time.Local を使う)。
func TestUIAuditPagerLinksKeepEveryFilter(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)
	machineID, _, err := CreateMachine(t.Context(), f.store.DB(), "app-prod", "web01", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	target := env.ProjectSlug + "/" + env.EnvSlug + "/DATABASE_URL"
	for i := range 60 {
		entry := machineAudit(machineID, "10.0.0.2", vaultNow.Add(time.Duration(i)*time.Second)).
			entry(ActionSecretRead, ResultSuccess, nil)
		entry.Target = &target
		entry.TargetEnvironmentID = &env.EnvironmentID
		mustRecord(t, f.store.DB(), entry)
	}

	filter := url.Values{
		"from": {"2000-01-01"}, "to": {"2100-01-01"},
		"actor":  {fmt.Sprintf("machine:%d", machineID)},
		"action": {"secret.read"}, "result": {"success"},
		"env": {fmt.Sprint(env.EnvironmentID)}, "n": {"50"},
	}
	// checkLink は、リンクが絞り込みと件数を保っていることを確かめ、位置の
	// パラメータ(before / after)の名前を返す。
	checkLink := func(name, href string) string {
		t.Helper()
		u, err := url.Parse(href)
		if err != nil || u.Path != "/ui/audit" {
			t.Fatalf("%s link %q: path %v, err %v", name, href, u, err)
		}
		if _, _, err := parseAuditQuery(u.RawQuery, time.UTC); err != nil {
			t.Fatalf("%s link %q does not parse: %v", name, href, err)
		}
		got := u.Query()
		var pos string
		for _, key := range []string{"before", "after"} {
			if got.Has(key) {
				pos += key
				got.Del(key)
			}
		}
		if got.Encode() != filter.Encode() {
			t.Errorf("%s link carries %q, want the filter %q", name, got.Encode(), filter.Encode())
		}
		return pos
	}
	countRows := func(body string) int { return strings.Count(body, `<td class="key">secret.read</td>`) }

	body := f.get(t, "/ui/audit?"+filter.Encode()).Body.String()
	if got := countRows(body); got != 50 {
		t.Fatalf("first page lists %d rows, want 50", got)
	}
	links := auditPagerLinks(t, body)
	if len(links) != 1 || links["古い方へ"] == "" {
		t.Fatalf("first page pager = %v, want only the link to older rows", links)
	}
	if pos := checkLink("older", links["古い方へ"]); pos != "before" {
		t.Errorf("older link positions by %q, want before", pos)
	}

	body = f.get(t, links["古い方へ"]).Body.String()
	if got := countRows(body); got != 10 {
		t.Errorf("second page lists %d rows, want 10", got)
	}
	// 絞り込みはフォームにも戻る(次に「絞り込む」を押しても条件が消えない)。
	for _, want := range []string{
		`name="from" value="2000-01-01"`, `name="to" value="2100-01-01"`,
		fmt.Sprintf(`<option value="machine:%d" selected>`, machineID),
		`<option value="secret.read" selected>`, `<option value="success" selected>`,
		fmt.Sprintf(`<option value="%d" selected>`, env.EnvironmentID),
		`<option value="50" selected>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the second page does not restore %q in the form", want)
		}
	}
	links = auditPagerLinks(t, body)
	if len(links) != 2 || links["新しい方へ"] == "" || links["最新へ"] == "" {
		t.Fatalf("second page pager = %v, want links to newer rows and to the newest page", links)
	}
	if pos := checkLink("newer", links["新しい方へ"]); pos != "after" {
		t.Errorf("newer link positions by %q, want after", pos)
	}
	if pos := checkLink("newest", links["最新へ"]); pos != "" {
		t.Errorf("newest link carries a position (%s)", pos)
	}

	// 新しい方へ戻ると、最初の 50 件に戻る。位置を持つページなので「最新へ」は残る。
	body = f.get(t, links["新しい方へ"]).Body.String()
	if got := countRows(body); got != 50 {
		t.Errorf("back on the newer page: %d rows, want 50", got)
	}
	back := auditPagerLinks(t, body)
	if back["新しい方へ"] != "" || back["古い方へ"] == "" {
		t.Errorf("back on the newer page: pager = %v, want older only (plus newest)", back)
	}

	body = f.get(t, links["最新へ"]).Body.String()
	if got := countRows(body); got != 50 {
		t.Errorf("newest page: %d rows, want 50", got)
	}
	if again := auditPagerLinks(t, body); len(again) != 1 || again["古い方へ"] == "" {
		t.Errorf("newest page pager = %v, want only the link to older rows", again)
	}
}

// 条件に合う行が無いときは、そう表示する。ページ送りは出さない。
func TestUIAuditPageSaysWhenNothingMatches(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)

	w := f.get(t, "/ui/audit?action=master.rotate&result=failure")
	if w.Code != http.StatusOK {
		t.Fatalf("audit page = %d, want 200 for a filter that matches nothing", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `class="empty">条件に合う記録がありません。</td>`) {
		t.Error("the page does not say that no record matches the filter")
	}
	if strings.Contains(body, `<nav class="pager">`) {
		t.Error("an empty page has a pager")
	}
	if !strings.Contains(body, `href="/ui/audit">解除</a>`) {
		t.Error("an empty filtered page has no link to clear the filter")
	}
	// 行が無い位置を手で指定しても同じ(最新へ戻るリンクだけが出る)。
	body = f.get(t, "/ui/audit?before=1-1").Body.String()
	if links := auditPagerLinks(t, body); len(links) != 1 || links["最新へ"] != "/ui/audit" {
		t.Errorf("a page beyond the oldest row: pager = %v, want only the link to the newest page", links)
	}
}

// **名前や記録された文字列にマークアップが入っていても、画面では文字として出る。**
//
// machine の名前は実行者の列、絞り込みの選択肢、対象の列に出る。target 列は
// 記録時点の文字列をそのまま出す(key の文字種は検証されるが、**画面は DB の
// 中身を信用しない**)。テンプレートを template.HTML に変えたり、文字列を連結して
// 出したりすると、ここが落ちる(ルール 40)。
func TestUIAuditPagesEscapeStoredStrings(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)
	db := f.store.DB()
	machineID, _, err := CreateMachine(t.Context(), db, "app-prod", "web01", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	// 入力の検証を通らない値が DB にある状態を作る。
	const (
		name      = `<script>alert(1)</script>`
		keyMarkup = `<img src=x onerror=alert(2)>`
		single    = `<b>alert(3)</b>`
	)
	if _, err := db.ExecContext(t.Context(), `UPDATE machines SET name = ? WHERE id = ?`, name, machineID); err != nil {
		t.Fatalf("rename machine: %v", err)
	}

	ac := machineAudit(machineID, "10.0.0.2", vaultNow)
	var entries []AuditEntry
	for _, key := range []string{"A", keyMarkup} {
		target := env.ProjectSlug + "/" + env.EnvSlug + "/" + key
		entry := ac.entry(ActionSecretRead, ResultSuccess, nil)
		entry.Target = &target
		entry.TargetEnvironmentID = &env.EnvironmentID
		entry.TargetMachineID = &machineID
		entries = append(entries, entry)
	}
	if err := recordBatch(t, db, entries); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	one := ac.entry(ActionSecretRead, ResultSuccess, nil)
	target := single
	one.Target = &target
	mustRecord(t, db, one)
	headID := auditBatchRows(t, db, ActionSecretRead)[0].ID

	pages := map[string]string{
		"list":                fmt.Sprintf("/ui/audit?actor=machine%%3A%d", machineID),
		"list without filter": "/ui/audit",
		"batch":               fmt.Sprintf("/ui/audit/batch/%d", headID),
	}
	for label, path := range pages {
		w := f.get(t, path)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: GET %s = %d", label, path, w.Code)
		}
		body := w.Body.String()
		for _, raw := range []string{"<script>alert(1)", "<img src=x", "<b>alert(3)"} {
			if strings.Contains(body, raw) {
				t.Errorf("%s page: %q is written as markup", label, raw)
			}
		}
		// 消えたのではなく、文字として出ていること。
		for _, escaped := range []string{html.EscapeString(name), "&lt;img src=x onerror=alert(2)&gt;"} {
			if !strings.Contains(body, escaped) {
				t.Errorf("%s page does not show %q as text", label, escaped)
			}
		}
	}

	list := f.get(t, pages["list"]).Body.String()
	option := fmt.Sprintf(`<option value="machine:%d" selected>%s (machine:%d)</option>`, machineID, html.EscapeString(name), machineID)
	if !strings.Contains(list, option) {
		t.Errorf("the actor filter does not show the machine as %q", option)
	}
	if !strings.Contains(list, "&lt;b&gt;alert(3)&lt;/b&gt;") {
		t.Error("the list does not show the single row's target as text")
	}
}

// **environment の行が引けない batch も、batch の画面に出る。**
//
// audit_logs は FK を持たない(ルール 57)。参照先が引けなくても、記録された
// 文字列から何が読まれたかが分かること。environment の id で絞り込むこともできる。
func TestUIAuditBatchPageWithoutItsEnvironmentRow(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	db := f.store.DB()
	machineID, _, err := CreateMachine(t.Context(), db, "app-prod", "web01", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}

	missingEnv := int64(99999)
	ac := machineAudit(machineID, "10.0.0.2", vaultNow)
	var entries []AuditEntry
	for _, key := range []string{"API_TOKEN", "SMTP_PASSWORD"} {
		target := "myapp/gone/" + key
		entry := ac.entry(ActionSecretRead, ResultSuccess, nil)
		entry.Target = &target
		entry.TargetEnvironmentID = &missingEnv
		entries = append(entries, entry)
	}
	if err := recordBatch(t, db, entries); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	headID := auditBatchRows(t, db, ActionSecretRead)[0].ID

	w := f.get(t, fmt.Sprintf("/ui/audit/batch/%d", headID))
	if w.Code != http.StatusOK {
		t.Fatalf("batch page = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"<td>myapp/gone</td>",
		`<td class="key">myapp/gone/API_TOKEN</td>`,
		`<td class="key">myapp/gone/SMTP_PASSWORD</td>`,
		fmt.Sprintf("<td>web01 (machine:%d)</td>", machineID),
		"同じ呼び出しで読まれた 2 件の key です。",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the batch page does not contain %q", want)
		}
	}

	// 選択肢に無い environment の id でも、URL で指定すれば絞り込める。
	w = f.get(t, "/ui/audit?env=99999")
	if w.Code != http.StatusOK {
		t.Fatalf("audit page filtered by a missing environment = %d, want 200", w.Code)
	}
	list := w.Body.String()
	if got := strings.Count(list, `<td class="key">secret.read</td>`); got != 1 {
		t.Errorf("filtering by the missing environment lists %d rows, want the batch as 1", got)
	}
	if !strings.Contains(list, "<summary>2 件の key</summary>") {
		t.Error("the list does not fold the batch of the missing environment")
	}
}

// **sealed の間は、監査ログの画面は全て unseal へ送られる。** 一度 unseal した後に
// seal した場合も同じ。クエリ文字列が不正でも、400 ではなく先に unseal へ送る
// (sealed の判定はハンドラより前にある)。
func TestUIAuditPagesRedirectWhileSealed(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t) // sealed のまま
	paths := []string{
		"/ui/audit?action=secret.read&n=50",
		"/ui/audit?before=1700000000-1",
		"/ui/audit?n=7",
		"/ui/audit/batch/1",
		"/ui/audit/batch/abc",
	}
	check := func(state string) {
		t.Helper()
		for _, path := range paths {
			w := f.get(t, path)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/unseal" {
				t.Errorf("%s, %s = %d %q, want a redirect to /ui/unseal", state, path, w.Code, w.Header().Get("Location"))
			}
			if strings.Contains(w.Body.String(), "<table") {
				t.Errorf("%s, %s: the redirect carries a table", state, path)
			}
		}
	}
	check("never unsealed")

	f.unseal(t)
	if w := f.get(t, paths[0]); w.Code != http.StatusOK {
		t.Fatalf("unsealed: %s = %d, want 200", paths[0], w.Code)
	}
	f.vault.Seal(t.Context(), f.auditCtx())
	check("sealed again")
}

// **監査ログの画面に、secret の値、client_secret、セッショントークンが出ない**
// (THREAT_MODEL §10.6)。
//
// 実際の操作(書き込み、reveal、machine の作成と credential の再発行)が残した
// 行と、bulk fetch の batch を、一覧と batch の画面の両方で見る。
func TestUIAuditPagesDoNotShowSecrets(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	env := f.seedSecret(t, "DATABASE_URL", testSecretValue)
	db := f.store.DB()

	// reveal は平文を返す。その監査行に値が入らないこと。
	w := f.post(t, "/ui/projects/"+env.ProjectSlug+"/"+env.EnvSlug+"/items/DATABASE_URL/reveal", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), html.EscapeString(testSecretValue)) {
		t.Fatalf("test setup: reveal = %d and does not show the value", w.Code)
	}
	machineID, clientSecret, err := CreateMachineWithGrant(t.Context(), db, "app-prod", "web01", env.EnvironmentID, f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachineWithGrant: %v", err)
	}

	ac := machineAudit(machineID, "10.0.0.2", vaultNow)
	var entries []AuditEntry
	for i, key := range []string{"DATABASE_URL", "API_TOKEN"} {
		target := env.ProjectSlug + "/" + env.EnvSlug + "/" + key
		version := int64(i + 1)
		entry := ac.entry(ActionSecretRead, ResultSuccess, &AuditDetail{Version: &version})
		entry.Target = &target
		entry.TargetEnvironmentID = &env.EnvironmentID
		entries = append(entries, entry)
	}
	if err := recordBatch(t, db, entries); err != nil {
		t.Fatalf("RecordAuditBatch: %v", err)
	}
	headID := auditBatchRows(t, db, ActionSecretRead)[0].ID

	if n := countAuditLogs(t, db, ActionSecretReveal); n != 1 {
		t.Fatalf("test setup: %d secret.reveal rows, want 1", n)
	}
	forbidden := map[string]string{
		"the secret value":          testSecretValue,
		"the escaped secret value":  html.EscapeString(testSecretValue),
		"the client_secret":         clientSecret,
		"the session token":         base64Session(f.rawSess),
		"the password in the value": "pass@localhost",
	}
	for _, path := range []string{"/ui/audit?n=200", "/ui/audit?action=secret.reveal", fmt.Sprintf("/ui/audit/batch/%d", headID)} {
		w := f.get(t, path)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, w.Code)
		}
		body := w.Body.String()
		for what, value := range forbidden {
			if value != "" && strings.Contains(body, value) {
				t.Errorf("GET %s shows %s", path, what)
			}
		}
		// 行そのものは出ている(空の画面を見て「漏れていない」と言わない)。
		if !strings.Contains(body, env.ProjectSlug+"/"+env.EnvSlug+"/DATABASE_URL") {
			t.Errorf("GET %s does not list the audited key at all", path)
		}
	}
}
