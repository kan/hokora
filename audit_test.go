package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// discardLogger はログ出力を捨てる。fail open の経路で使う。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func ptr[T any](v T) *T { return &v }

// countAuditLogs は監査ログの件数を数える。
func countAuditLogs(t *testing.T, db *sql.DB, action Action) int {
	t.Helper()

	var n int
	if err := db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM audit_logs WHERE action = ?`, string(action),
	).Scan(&n); err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	return n
}

func TestRecordAuditRoundTrip(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	at := time.Unix(1700000000, 0)

	entry := AuditEntry{
		At:              at,
		Actor:           actorMachine(7),
		ActorMachineID:  ptr(int64(7)),
		Action:          ActionSecretRead,
		Target:          ptr("myapp/prod/DATABASE_URL"),
		TargetProjectID: ptr(int64(1)),
		TargetItemID:    ptr(int64(3)),
		Result:          ResultSuccess,
		RemoteAddr:      ptr("10.0.0.2"),
		Detail:          &AuditDetail{Version: ptr(2)},
	}
	if err := RecordAudit(t.Context(), store.DB(), entry); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	var (
		gotAt                  int64
		actor, action, result  string
		machineID, itemID      sql.NullInt64
		target, remote, detail sql.NullString
	)
	if err := store.DB().QueryRowContext(t.Context(), `
		SELECT at, actor, actor_machine_id, action, target, target_item_id, result, remote_addr, detail
		FROM audit_logs`,
	).Scan(&gotAt, &actor, &machineID, &action, &target, &itemID, &result, &remote, &detail); err != nil {
		t.Fatalf("select audit log: %v", err)
	}

	if gotAt != at.Unix() {
		t.Errorf("at = %d, want %d", gotAt, at.Unix())
	}
	if actor != "machine:7" || !machineID.Valid || machineID.Int64 != 7 {
		t.Errorf("actor = %q / machine id = %v, want machine:7 / 7", actor, machineID)
	}
	if action != string(ActionSecretRead) || result != string(ResultSuccess) {
		t.Errorf("action/result = %q/%q", action, result)
	}
	// 表示用の target と immutable ID の両方が残ること(THREAT_MODEL §10.2)。
	if !target.Valid || target.String != "myapp/prod/DATABASE_URL" {
		t.Errorf("target = %v", target)
	}
	if !itemID.Valid || itemID.Int64 != 3 {
		t.Errorf("target_item_id = %v, want 3", itemID)
	}
	if !detail.Valid {
		t.Fatal("detail is NULL")
	}
	var gotDetail AuditDetail
	if err := json.Unmarshal([]byte(detail.String), &gotDetail); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if gotDetail.Version == nil || *gotDetail.Version != 2 {
		t.Errorf("detail.version = %v, want 2", gotDetail.Version)
	}
}

// detail が空のときは NULL になる(空の JSON オブジェクトを書かない)。
func TestRecordAuditEmptyDetailIsNull(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	for _, detail := range []*AuditDetail{nil, {}} {
		if err := RecordAudit(t.Context(), store.DB(), AuditEntry{
			At: time.Unix(1700000000, 0), Actor: ActorAnonymous,
			Action: ActionSeal, Result: ResultSuccess, Detail: detail,
		}); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}

	var nonNull int
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM audit_logs WHERE detail IS NOT NULL`).Scan(&nonNull); err != nil {
		t.Fatalf("count: %v", err)
	}
	if nonNull != 0 {
		t.Errorf("%d rows have a non-NULL detail, want 0", nonNull)
	}
}

// allowlist に無い action / reason / via、および actor の不整合は DB に届かない。
func TestRecordAuditRejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	at := time.Unix(1700000000, 0)

	tests := []struct {
		name  string
		entry AuditEntry
	}{
		{"unknown action", AuditEntry{At: at, Actor: ActorAnonymous, Action: "secret.exfiltrate", Result: ResultSuccess}},
		{"empty action", AuditEntry{At: at, Actor: ActorAnonymous, Action: "", Result: ResultSuccess}},
		{"unknown result", AuditEntry{At: at, Actor: ActorAnonymous, Action: ActionSeal, Result: "partial"}},
		{"zero time", AuditEntry{Actor: ActorAnonymous, Action: ActionSeal, Result: ResultSuccess}},

		// 攻撃者制御の文字列を actor に入れる経路を塞ぐ(DESIGN §5.5)。
		{"raw client id as actor", AuditEntry{
			At: at, Actor: "app-prod\nadmin", Action: ActionAuthMachine, Result: ResultFailure,
		}},
		{"actor does not match user id", AuditEntry{
			At: at, Actor: "user:2", ActorUserID: ptr(int64(1)),
			Action: ActionAuthUser, Result: ResultSuccess,
		}},
		{"actor does not match machine id", AuditEntry{
			At: at, Actor: ActorAnonymous, ActorMachineID: ptr(int64(1)),
			Action: ActionAuthMachine, Result: ResultSuccess,
		}},
		{"both actor ids", AuditEntry{
			At: at, Actor: "user:1", ActorUserID: ptr(int64(1)), ActorMachineID: ptr(int64(1)),
			Action: ActionAuthUser, Result: ResultSuccess,
		}},

		{"unknown reason", AuditEntry{
			At: at, Actor: ActorAnonymous, Action: ActionAuthMachine, Result: ResultFailure,
			Detail: &AuditDetail{Reason: ptr("because the client_id was 'ci-runner'")},
		}},
		{"unknown via", AuditEntry{
			At: at, Actor: ActorAnonymous, Action: ActionSeal, Result: ResultSuccess,
			Detail: &AuditDetail{Via: ptr("cli")},
		}},
		{"raw subject digest", AuditEntry{
			At: at, Actor: ActorAnonymous, Action: ActionAuthMachine, Result: ResultFailure,
			Detail: &AuditDetail{SubjectDigest: ptr("app-prod")},
		}},
		{"short subject digest", AuditEntry{
			At: at, Actor: ActorAnonymous, Action: ActionAuthMachine, Result: ResultFailure,
			Detail: &AuditDetail{SubjectDigest: ptr("abcd")},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := RecordAudit(t.Context(), store.DB(), tt.entry); err == nil {
				t.Fatal("RecordAudit accepted an invalid entry")
			}
		})
	}

	var n int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_logs`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d invalid entries reached the database", n)
	}
}

// allowlist に載っている値は全て通ること。定数を足したのに allowlist へ
// 入れ忘れると、その action が記録できないまま気付かれない。
func TestAuditAllowlistAcceptsEveryDefinedAction(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	actions := []Action{
		ActionSecretRead, ActionSecretWrite, ActionSecretDelete, ActionSecretReveal,
		ActionUnsealAttempt, ActionSeal, ActionMasterRotate,
		ActionAuthMachine, ActionAuthUser, ActionLogout,
		ActionUserCreate, ActionUserDisable, ActionUserPasswordChange,
		ActionMachineCreate, ActionMachineDisable, ActionMachineRotateSecret,
		ActionGrantCreate, ActionGrantDelete,
		ActionProjectCreate, ActionProjectDelete,
		ActionEnvironmentCreate, ActionEnvironmentDelete,
	}
	if len(actions) != len(auditActions) {
		t.Fatalf("allowlist has %d entries but the test covers %d", len(auditActions), len(actions))
	}

	for _, action := range actions {
		if err := RecordAudit(t.Context(), store.DB(), AuditEntry{
			At: time.Unix(1700000000, 0), Actor: ActorAnonymous,
			Action: action, Result: ResultSuccess,
		}); err != nil {
			t.Errorf("RecordAudit(%q): %v", action, err)
		}
	}
}

func TestAuditReasonAllowlist(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	reasons := []string{
		ReasonInvalidCredentials, ReasonRateLimited, ReasonForbidden, ReasonSealed,
		ReasonDisabled, ReasonExpired, ReasonInvalidCSRF, ReasonInvalidMasterKey,
	}
	if len(reasons) != len(auditReasons) {
		t.Fatalf("allowlist has %d reasons but the test covers %d", len(auditReasons), len(reasons))
	}

	for _, reason := range reasons {
		if err := RecordAudit(t.Context(), store.DB(), AuditEntry{
			At: time.Unix(1700000000, 0), Actor: ActorAnonymous,
			Action: ActionAuthMachine, Result: ResultFailure,
			Detail: &AuditDetail{Reason: &reason},
		}); err != nil {
			t.Errorf("RecordAudit(reason=%q): %v", reason, err)
		}
	}
}

// RecordAuditBestEffort は失敗しても呼び出し側を止めない(fail open)。
func TestRecordAuditBestEffortDoesNotPropagateFailures(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	breakAuditTable(t, store)

	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	// 戻り値が無いので、パニックせず戻ることと、ログに出ることを確かめる。
	RecordAuditBestEffort(t.Context(), store.DB(), logger, AuditEntry{
		At: time.Unix(1700000000, 0), Actor: ActorAnonymous,
		Action: ActionSeal, Result: ResultSuccess,
	})

	out := logged.String()
	if !strings.Contains(out, "fail open") {
		t.Errorf("the failure was not logged: %q", out)
	}
	// 運用ログに entry 全体をダンプしない(将来 detail に足した値が漏れる)。
	if strings.Contains(out, "AuditEntry{") {
		t.Errorf("the log dumps the whole entry: %q", out)
	}
}

// ---- auditCtx(誰が・どこから・いつ) ----

// socketAudit は「socket に居るのが誰かまでは分からない」ことを表す。
// ここで actor に何かを入れる実装に変わると、その値の出所が問題になる。
func TestSocketAuditContext(t *testing.T) {
	t.Parallel()

	ac := socketAudit(time.Unix(1700000000, 0))
	if ac.Actor != ActorAnonymous {
		t.Errorf("actor = %q, want %q", ac.Actor, ActorAnonymous)
	}
	if ac.ActorUserID != nil {
		t.Errorf("actor user id = %v, want nil", ac.ActorUserID)
	}
	if ac.Via != ViaSocket {
		t.Errorf("via = %q, want %q", ac.Via, ViaSocket)
	}
	// unix socket に送信元アドレスは無い。作り話を入れない。
	if ac.RemoteAddr != nil {
		t.Errorf("remote addr = %v, want nil", ac.RemoteAddr)
	}
}

// entry は「誰が・どこから・いつ」を欠かさず載せ、**呼び出し側が渡した
// detail を壊さない**。Via が落ちると、socket 経由と Web UI 経由の区別が
// 監査ログから消える。
func TestAuditCtxEntry(t *testing.T) {
	t.Parallel()

	at := time.Unix(1700000000, 0)

	t.Run("fills via when the caller passes no detail", func(t *testing.T) {
		t.Parallel()

		e := socketAudit(at).entry(ActionSeal, ResultSuccess, nil)
		if e.Detail == nil || e.Detail.Via == nil || *e.Detail.Via != ViaSocket {
			t.Fatalf("detail = %+v, want via = %q", e.Detail, ViaSocket)
		}
		if e.Actor != ActorAnonymous || !e.At.Equal(at) {
			t.Errorf("entry = %+v, want the actor and time from the context", e)
		}
		if e.Action != ActionSeal || e.Result != ResultSuccess {
			t.Errorf("action/result = %q/%q", e.Action, e.Result)
		}
	})

	t.Run("keeps the caller's detail fields", func(t *testing.T) {
		t.Parallel()

		reason := ReasonInvalidMasterKey
		digest := subjectDigest("app-prod")
		e := socketAudit(at).entry(ActionUnsealAttempt, ResultFailure, &AuditDetail{
			Reason: &reason, SubjectDigest: &digest, Count: ptr(3),
		})
		switch {
		case e.Detail.Reason == nil || *e.Detail.Reason != reason:
			t.Errorf("reason = %v, want %q", e.Detail.Reason, reason)
		case e.Detail.SubjectDigest == nil || *e.Detail.SubjectDigest != digest:
			t.Errorf("subject digest = %v, want %q", e.Detail.SubjectDigest, digest)
		case e.Detail.Count == nil || *e.Detail.Count != 3:
			t.Errorf("count = %v, want 3", e.Detail.Count)
		case e.Detail.Via == nil || *e.Detail.Via != ViaSocket:
			t.Errorf("via = %v, want %q", e.Detail.Via, ViaSocket)
		}
	})

	t.Run("does not overwrite an explicit via", func(t *testing.T) {
		t.Parallel()

		e := socketAudit(at).entry(ActionSeal, ResultSuccess, &AuditDetail{Via: ptr(ViaWeb)})
		if e.Detail.Via == nil || *e.Detail.Via != ViaWeb {
			t.Errorf("via = %v, want the caller's value %q", e.Detail.Via, ViaWeb)
		}
	})

	t.Run("web context carries the user and the remote address", func(t *testing.T) {
		t.Parallel()

		ac := auditCtx{
			Actor: actorUser(4), ActorUserID: ptr(int64(4)),
			Via: ViaWeb, RemoteAddr: ptr("10.0.0.9"), Now: at,
		}
		e := ac.entry(ActionSecretReveal, ResultSuccess, nil)
		switch {
		case e.Actor != "user:4" || e.ActorUserID == nil || *e.ActorUserID != 4:
			t.Errorf("actor = %q / %v, want user:4 / 4", e.Actor, e.ActorUserID)
		case e.RemoteAddr == nil || *e.RemoteAddr != "10.0.0.9":
			t.Errorf("remote addr = %v, want 10.0.0.9", e.RemoteAddr)
		case e.Detail.Via == nil || *e.Detail.Via != ViaWeb:
			t.Errorf("via = %v, want %q", e.Detail.Via, ViaWeb)
		}
		// 組み立てた行がそのまま記録できること(validate を通ること)。
		if err := RecordAudit(t.Context(), newTestStore(t).DB(), e); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	})

	t.Run("via is empty when the context has none", func(t *testing.T) {
		t.Parallel()

		e := auditCtx{Actor: ActorAnonymous, Now: at}.entry(ActionSeal, ResultSuccess, nil)
		if e.Detail.Via != nil {
			t.Errorf("via = %v, want nil", e.Detail.Via)
		}
		// 全て空の detail は NULL になる(空の JSON を書かない)。
		got, err := e.marshalDetail()
		if err != nil {
			t.Fatalf("marshalDetail: %v", err)
		}
		if got != nil {
			t.Errorf("detail = %v, want NULL", got)
		}
	})
}

// via が実際に detail 列へ入ること。entry で組み立てただけでは、JSON の
// タグ名が変わったことに気付けない。
func TestAuditViaIsPersisted(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if err := RecordAudit(t.Context(), store.DB(),
		socketAudit(time.Unix(1700000000, 0)).entry(ActionSeal, ResultSuccess, nil)); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	var detail string
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT detail FROM audit_logs WHERE action = ?`, string(ActionSeal)).Scan(&detail); err != nil {
		t.Fatalf("select: %v", err)
	}
	var got AuditDetail
	if err := json.Unmarshal([]byte(detail), &got); err != nil {
		t.Fatalf("unmarshal detail: %v (raw %q)", err, detail)
	}
	if got.Via == nil || *got.Via != ViaSocket {
		t.Errorf("detail = %q, want via = %q", detail, ViaSocket)
	}
}

// subjectDigest は生の入力を残さず、固定長で、決定的である(DESIGN §5.5)。
func TestSubjectDigest(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"app-prod",
		"", // 空入力でも固定長
		"admin\nDROP TABLE audit_logs;--",
		strings.Repeat("a", 4096),
		"日本語の client_id",
	}

	seen := make(map[string]string, len(inputs))
	for _, in := range inputs {
		got := subjectDigest(in)
		if len(got) != 16 {
			t.Errorf("subjectDigest(%q) has length %d, want 16", in, len(got))
		}
		if in != "" && strings.Contains(got, in) {
			t.Errorf("subjectDigest(%q) contains the raw input", in)
		}
		if strings.ContainsAny(got, "\n\r\t ") {
			t.Errorf("subjectDigest(%q) = %q contains whitespace", in, got)
		}
		if got != subjectDigest(in) {
			t.Errorf("subjectDigest(%q) is not deterministic", in)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("subjectDigest collision between %q and %q", in, prev)
		}
		seen[got] = in
	}

	// 記録できる形式であること。
	store := newTestStore(t)
	digest := subjectDigest("does-not-exist")
	if err := RecordAudit(t.Context(), store.DB(), AuditEntry{
		At: time.Unix(1700000000, 0), Actor: ActorAnonymous,
		Action: ActionAuthMachine, Result: ResultFailure,
		Detail: &AuditDetail{Reason: ptr(ReasonInvalidCredentials), SubjectDigest: &digest},
	}); err != nil {
		t.Fatalf("RecordAudit with a subject digest: %v", err)
	}
}

// breakAuditTable は監査ログを書けない状態を作る。
//
// 「監査 DB が壊れている」状況を再現するために、テーブルそのものを落とす。
// 監査の fail closed / fail open は、この状態で挙動が分かれることが本質である。
func breakAuditTable(t *testing.T, store *Store) {
	t.Helper()

	if _, err := store.DB().ExecContext(t.Context(), `DROP TABLE audit_logs`); err != nil {
		t.Fatalf("drop audit_logs: %v", err)
	}
}
