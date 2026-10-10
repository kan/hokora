package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- machine ごとの認証の上限(#28) ----

// storedAuthRate は machines.auth_rate_per_minute を、保存されたまま返す。
func storedAuthRate(t *testing.T, db *sql.DB, machineID int64) sql.NullInt64 {
	t.Helper()

	var stored sql.NullInt64
	if err := db.QueryRowContext(t.Context(),
		`SELECT auth_rate_per_minute FROM machines WHERE id = ?`, machineID).Scan(&stored); err != nil {
		t.Fatalf("read auth_rate_per_minute: %v", err)
	}
	return stored
}

func mustSetAuthRate(t *testing.T, db *sql.DB, machineID int64, rate int) {
	t.Helper()

	if err := SetMachineAuthRate(t.Context(), db, discardLogger(), machineID, rate,
		auditCtx{Actor: ActorAnonymous, Now: vaultNow}); err != nil {
		t.Fatalf("SetMachineAuthRate(%d): %v", rate, err)
	}
}

// rateFixture は、machine を 1 つ持つ DB である。**vault は開けない**(設定の
// 読み書きだけを見るテストで、unseal の argon2 を回さない)。
type rateFixture struct {
	store     *Store
	machineID int64
	clientID  string
}

func newRateFixture(t *testing.T) *rateFixture {
	t.Helper()

	f := &rateFixture{store: newTestStore(t), clientID: "app-prod"}
	id, _, err := CreateMachine(t.Context(), f.store.DB(), f.clientID, "app server",
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	f.machineID = id
	return f
}

// authFrom は、指定した送信元から認証する。
func (f *apiFixture) authFrom(t *testing.T, clientID, secret, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()

	return f.doFrom(t, remoteAddr, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: clientID, ClientSecret: secret})
}

// **上げた machine は、上げた回数まで認証できる。** 既定値のままの machine は
// 変わらない(上限は machine ごとであって、全体ではない)。
func TestAPIAuthRateIsPerMachine(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	otherID, otherSecret, err := CreateMachine(t.Context(), f.store.DB(), "other-app", "other",
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	const raised = 20
	mustSetAuthRate(t, f.store.DB(), f.machineID, raised)

	// 成功した認証も数える。送信元は 1 つ(第一段の 30 回には届かない)。
	for i := range raised {
		if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusOK {
			t.Fatalf("attempt %d = %d, want 200 (body %q)", i+1, w.Code, w.Body.String())
		}
	}
	if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", raised+1, w.Code)
	}

	// 別の machine は既定値のまま。別の送信元から試す(第一段を分ける)。
	for i := range authTokenRatePerClientID {
		if w := f.authFrom(t, "other-app", otherSecret, "10.0.0.3:5000"); w.Code != http.StatusOK {
			t.Fatalf("other machine: attempt %d = %d, want 200", i+1, w.Code)
		}
	}
	if w := f.authFrom(t, "other-app", otherSecret, "10.0.0.3:5000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("other machine (id %d): attempt %d = %d, want 429", otherID, authTokenRatePerClientID+1, w.Code)
	}
}

// **第一段(送信元 IP)は、machine の設定では上がらない**(ルール 35)。
// 上限を最大にした machine でも、1 つの送信元からは 30 回までである。
func TestAPIAuthRateDoesNotRaiseTheIPLimit(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerIP)

	for i := range authTokenRatePerIP {
		if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusOK {
			t.Fatalf("attempt %d = %d, want 200", i+1, w.Code)
		}
	}
	before := countAuditLogs(t, f.store.DB(), ActionAuthMachine)
	if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429 from the per-IP limit", authTokenRatePerIP+1, w.Code)
	}
	// 第一段の拒否は記録しない(従来どおり)。第二段で弾かれたのなら 1 行増える。
	if after := countAuditLogs(t, f.store.DB(), ActionAuthMachine); after != before {
		t.Errorf("auth.machine rows went from %d to %d: the request was rejected by the second stage", before, after)
	}
}

// **存在しない client_id は、既定値で数える。** 上限を上げた machine があっても、
// 他の client_id の上限は変わらない。
func TestAPIAuthRateForUnknownClientIDIsTheDefault(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerIP)

	for i := range authTokenRatePerClientID {
		// 送信元を毎回変えて、第一段を避ける。
		w := f.authFrom(t, "no-such-client", "x", fmt.Sprintf("10.1.0.%d:5000", i+1))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	if w := f.authFrom(t, "no-such-client", "x", "10.1.1.1:5000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", authTokenRatePerClientID+1, w.Code)
	}
}

// **下げた上限は、その窓の残りにもすぐ効く**(数えた回数は持ち越す)。
func TestAPIAuthRateLoweredTakesEffectAtOnce(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	mustSetAuthRate(t, f.store.DB(), f.machineID, 20)
	for i := range 12 {
		if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusOK {
			t.Fatalf("attempt %d = %d, want 200", i+1, w.Code)
		}
	}

	mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerClientID)
	if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after lowering the limit below the count: %d, want 429", w.Code)
	}
}

// **429 は、いつ再試行してよいかを Retry-After で返す。** 第一段でも第二段でも。
func TestAPIRateLimitedResponseHasRetryAfter(t *testing.T) {
	t.Parallel()

	t.Run("second stage", func(t *testing.T) {
		t.Parallel()

		f := newAPIFixture(t)
		now := vaultNow
		f.api.now = func() time.Time { return now }

		for i := range authTokenRatePerClientID {
			if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusOK {
				t.Fatalf("attempt %d = %d, want 200", i+1, w.Code)
			}
		}
		// 窓が開いてから 12.5 秒後に弾かれる。残りは 47.5 秒で、切り上げて 48。
		now = vaultNow.Add(12*time.Second + 500*time.Millisecond)
		w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", w.Code)
		}
		if got := w.Header().Get("Retry-After"); got != "48" {
			t.Errorf("Retry-After = %q, want 48", got)
		}

		// 言われたとおりに待てば通る。
		now = vaultNow.Add(48 * time.Second)
		if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusTooManyRequests {
			t.Fatalf("at 48s the window (60s) is still open, got %d", w.Code)
		}
		now = vaultNow.Add(12*time.Second + 500*time.Millisecond + 48*time.Second)
		if w := f.authFrom(t, f.clientID, f.secret, "10.0.0.2:5000"); w.Code != http.StatusOK {
			t.Fatalf("after waiting Retry-After seconds: %d, want 200", w.Code)
		}
	})

	t.Run("first stage", func(t *testing.T) {
		t.Parallel()

		f := newAPIFixture(t)
		var last *httptest.ResponseRecorder
		for i := range authTokenRatePerIP + 1 {
			last = f.authFrom(t, fmt.Sprintf("client-%d", i), "x", "10.0.0.2:5000")
		}
		if last.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", last.Code)
		}
		if got := last.Header().Get("Retry-After"); got != "60" {
			t.Errorf("Retry-After = %q, want 60", got)
		}
	})
}

func TestRetryAfterSeconds(t *testing.T) {
	t.Parallel()

	tests := map[time.Duration]int{
		0:                       1,
		-time.Second:            1,
		time.Nanosecond:         1,
		time.Second:             1,
		time.Second + 1:         2,
		59*time.Second + 999999: 60,
		time.Minute:             60,
	}
	for wait, want := range tests {
		if got := retryAfterSeconds(wait); got != want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", wait, got, want)
		}
	}
}

// Take は、呼び出しごとの上限で数える。Allow の上限(作ったときの値)とは独立である。
func TestRateLimiterTake(t *testing.T) {
	t.Parallel()

	r := newRateLimiter(1, 0)
	for i := range 3 {
		if ok, wait := r.Take("k", 3, vaultNow); !ok || wait != 0 {
			t.Fatalf("attempt %d: ok = %v, wait = %v", i+1, ok, wait)
		}
	}
	ok, wait := r.Take("k", 3, vaultNow.Add(20*time.Second))
	if ok || wait != 40*time.Second {
		t.Errorf("over the limit: ok = %v, wait = %v, want false and 40s", ok, wait)
	}
	// 上限を上げれば、同じ窓の中でも通る。
	if ok, _ := r.Take("k", 4, vaultNow.Add(20*time.Second)); !ok {
		t.Error("a raised limit did not apply within the window")
	}

	// map が一杯で新しいキーを受け入れられないときは、窓 1 つぶんを返す。
	full := newRateLimiter(1, 1)
	full.Take("a", 1, vaultNow)
	if ok, wait := full.Take("b", 1, vaultNow); ok || wait != rateWindow {
		t.Errorf("full map: ok = %v, wait = %v, want false and %v", ok, wait, rateWindow)
	}
}

// ---- SetMachineAuthRate ----

func TestSetMachineAuthRate(t *testing.T) {
	t.Parallel()

	f := newRateFixture(t)
	db := f.store.DB()

	if got := storedAuthRate(t, db, f.machineID); got.Valid {
		t.Fatalf("a new machine has auth_rate_per_minute = %d, want NULL", got.Int64)
	}

	mustSetAuthRate(t, f.store.DB(), f.machineID, 25)
	if got := storedAuthRate(t, db, f.machineID); !got.Valid || got.Int64 != 25 {
		t.Errorf("stored = %+v, want 25", got)
	}
	if rate, err := MachineAuthRate(t.Context(), db, f.clientID); err != nil || rate != 25 {
		t.Errorf("MachineAuthRate = %d, %v, want 25", rate, err)
	}

	// **既定値は NULL として保存する**(既定値を変えたら追随する)。
	mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerClientID)
	if got := storedAuthRate(t, db, f.machineID); got.Valid {
		t.Errorf("stored = %d after setting the default, want NULL", got.Int64)
	}

	// 監査: 設定した値と対象の machine を残す。
	rows := queryStrings(t, db, `
		SELECT COALESCE(detail, '') || ' machine=' || target_machine_id || ' ' || result
		FROM audit_logs WHERE action = 'machine.set_auth_rate' ORDER BY id`)
	want := []string{
		fmt.Sprintf(`{"rate":25} machine=%d success`, f.machineID),
		fmt.Sprintf(`{"rate":%d} machine=%d success`, authTokenRatePerClientID, f.machineID),
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit rows:\n%s\nwant:\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}
}

func TestSetMachineAuthRateRejectsOutOfRange(t *testing.T) {
	t.Parallel()

	f := newRateFixture(t)
	for _, rate := range []int{-1, 0, 1, authTokenRatePerClientID - 1, authTokenRatePerIP + 1, 1 << 40} {
		err := SetMachineAuthRate(t.Context(), f.store.DB(), discardLogger(), f.machineID, rate,
			auditCtx{Actor: ActorAnonymous, Now: vaultNow})
		if !errors.Is(err, errAuthRateOutOfRange) {
			t.Errorf("rate %d: err = %v, want errAuthRateOutOfRange", rate, err)
		}
	}
	if got := storedAuthRate(t, f.store.DB(), f.machineID); got.Valid {
		t.Errorf("stored = %d, want NULL", got.Int64)
	}
	if n := countAuditLogs(t, f.store.DB(), ActionMachineSetAuthRate); n != 0 {
		t.Errorf("%d audit rows for rejected values, want 0", n)
	}
}

func TestSetMachineAuthRateUnknownMachine(t *testing.T) {
	t.Parallel()

	f := newRateFixture(t)
	for _, rate := range []int{authTokenRatePerClientID, 20} {
		err := SetMachineAuthRate(t.Context(), f.store.DB(), discardLogger(), f.machineID+100, rate,
			auditCtx{Actor: ActorAnonymous, Now: vaultNow})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("rate %d: err = %v, want ErrNotFound", rate, err)
		}
	}
	if n := countAuditLogs(t, f.store.DB(), ActionMachineSetAuthRate); n != 0 {
		t.Errorf("%d audit rows for a missing machine, want 0", n)
	}
}

// **監査が書けないとき、上げる操作は通さず、下げる操作は通す**(ルール 26 / 27)。
func TestSetMachineAuthRateAuditFailure(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		from, to   int
		wantErr    bool
		wantStored int // 0 は NULL
	}{
		"raise is refused (fail closed)":                {from: 15, to: 20, wantErr: true, wantStored: 15},
		"raise from the default is refused":             {from: 10, to: 11, wantErr: true, wantStored: 0},
		"lower goes through (fail open)":                {from: 25, to: 15, wantStored: 15},
		"reset to the default goes through (fail open)": {from: 25, to: 10, wantStored: 0},
		"same value goes through":                       {from: 25, to: 25, wantStored: 25},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newRateFixture(t)
			mustSetAuthRate(t, f.store.DB(), f.machineID, tt.from)
			breakAuditTable(t, f.store)

			err := SetMachineAuthRate(t.Context(), f.store.DB(), discardLogger(), f.machineID, tt.to,
				auditCtx{Actor: ActorAnonymous, Now: vaultNow})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			got := storedAuthRate(t, f.store.DB(), f.machineID)
			if got.Valid != (tt.wantStored != 0) || (got.Valid && got.Int64 != int64(tt.wantStored)) {
				t.Errorf("stored = %+v, want %d (0 = NULL)", got, tt.wantStored)
			}
		})
	}
}

// **いまの上限と同じ値なら、何も書かない。** 一覧の「変更」を、値を変えずに
// 押すたびに監査行が増え、updated_at が動くのを防ぐ。
func TestSetMachineAuthRateSameValueWritesNothing(t *testing.T) {
	t.Parallel()

	f := newRateFixture(t)
	db := f.store.DB()
	later := auditCtx{Actor: ActorAnonymous, Now: vaultNow.Add(time.Hour)}

	for _, rate := range []int{authTokenRatePerClientID, 20, 20} {
		if rate == 20 {
			mustSetAuthRate(t, db, f.machineID, 20)
		}
		before := queryStrings(t, db, `SELECT updated_at FROM machines`)
		rows := countAuditLogs(t, db, ActionMachineSetAuthRate)

		if err := SetMachineAuthRate(t.Context(), db, discardLogger(), f.machineID, rate, later); err != nil {
			t.Fatalf("SetMachineAuthRate(%d) again: %v", rate, err)
		}
		if after := queryStrings(t, db, `SELECT updated_at FROM machines`); after[0] != before[0] {
			t.Errorf("rate %d: updated_at moved from %s to %s", rate, before[0], after[0])
		}
		if got := countAuditLogs(t, db, ActionMachineSetAuthRate); got != rows {
			t.Errorf("rate %d: audit rows went from %d to %d", rate, rows, got)
		}
	}
}

// **向きは、保存された値ではなく、実際に効いている上限と比べて決める。**
// 範囲の外の古い値(定数を変えた後に残る)が保存されていても、実際には下げる
// 操作、同じ値にする操作を、監査の障害で止めない。
func TestSetMachineAuthRateComparesTheEffectiveLimit(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		stored  int64 // 範囲の外の、保存された値
		to      int
		wantErr bool
		want    sql.NullInt64
	}{
		// 保存は 40 でも、効いているのは 30。20 にするのは下げる操作である。
		"above the range, lowered":    {stored: 40, to: 20, want: sql.NullInt64{Int64: 20, Valid: true}},
		"above the range, same":       {stored: 40, to: 30, want: sql.NullInt64{Int64: 40, Valid: true}},
		"below the range, to default": {stored: 5, to: 10, want: sql.NullInt64{Int64: 5, Valid: true}},
		// 保存は 5 でも、効いているのは 10。11 にするのは上げる操作である。
		"below the range, raised": {stored: 5, to: 11, wantErr: true, want: sql.NullInt64{Int64: 5, Valid: true}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newRateFixture(t)
			db := f.store.DB()
			if _, err := db.ExecContext(t.Context(),
				`UPDATE machines SET auth_rate_per_minute = ? WHERE id = ?`, tt.stored, f.machineID); err != nil {
				t.Fatalf("store %d: %v", tt.stored, err)
			}
			breakAuditTable(t, f.store)

			err := SetMachineAuthRate(t.Context(), db, discardLogger(), f.machineID, tt.to,
				auditCtx{Actor: ActorAnonymous, Now: vaultNow})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got := storedAuthRate(t, db, f.machineID); got != tt.want {
				t.Errorf("stored = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// 範囲の外の値が保存されていても(定数を変えた後の古い値)、読む側で範囲に収める。
func TestMachineAuthRateClampsStoredValues(t *testing.T) {
	t.Parallel()

	f := newRateFixture(t)
	tests := map[int64]int{
		1:       authTokenRatePerClientID,
		9:       authTokenRatePerClientID,
		10:      10,
		30:      30,
		31:      authTokenRatePerIP,
		1 << 40: authTokenRatePerIP,
	}
	for stored, want := range tests {
		if _, err := f.store.DB().ExecContext(t.Context(),
			`UPDATE machines SET auth_rate_per_minute = ? WHERE id = ?`, stored, f.machineID); err != nil {
			t.Fatalf("store %d: %v", stored, err)
		}
		if got, err := MachineAuthRate(t.Context(), f.store.DB(), f.clientID); err != nil || got != want {
			t.Errorf("stored %d: MachineAuthRate = %d, %v, want %d", stored, got, err, want)
		}
	}

	// スキーマは 0 以下を受け付けない。
	for _, bad := range []int{0, -5} {
		if _, err := f.store.DB().ExecContext(t.Context(),
			`UPDATE machines SET auth_rate_per_minute = ? WHERE id = ?`, bad, f.machineID); err == nil {
			t.Errorf("the schema accepted auth_rate_per_minute = %d", bad)
		}
	}
}

// ---- Web UI ----

func TestUISetMachineAuthRate(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}

	body := f.get(t, "/ui/machines").Body.String()
	wantInput := fmt.Sprintf(`name="rate" value="%d" min="%d" max="%d"`,
		authTokenRatePerClientID, authTokenRatePerClientID, authTokenRatePerIP)
	if !strings.Contains(body, `action="/ui/machines/1/auth-rate"`) || !strings.Contains(body, wantInput) {
		t.Fatalf("the machine list has no form for the auth rate (want %s)", wantInput)
	}

	if w := f.post(t, "/ui/machines/1/auth-rate", url.Values{"rate": {"20"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("set auth rate = %d (body %q)", w.Code, w.Body.String())
	}
	if got := storedAuthRate(t, f.vault.db, 1); !got.Valid || got.Int64 != 20 {
		t.Errorf("stored = %+v, want 20", got)
	}
	if body := f.get(t, "/ui/machines").Body.String(); !strings.Contains(body, `name="rate" value="20"`) {
		t.Error("the machine list does not show the new auth rate")
	}

	// 監査の実行者は、操作した admin である。
	actors := queryStrings(t, f.vault.db,
		`SELECT actor_user_id IS NOT NULL FROM audit_logs WHERE action = 'machine.set_auth_rate'`)
	if len(actors) != 1 || actors[0] != "1" {
		t.Errorf("audit rows (actor_user_id set?) = %v, want [1]", actors)
	}
}

func TestUISetMachineAuthRateRejectsBadInput(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}

	for _, raw := range []string{"", "9", "31", "0", "-20", "+20", " 20", "20 ", "020", "2e1", "20.0", "abc", "99999999999999999999"} {
		w := f.post(t, "/ui/machines/1/auth-rate", url.Values{"rate": {raw}})
		if w.Code != http.StatusBadRequest {
			t.Errorf("rate %q = %d, want 400", raw, w.Code)
		}
		// 入力をそのまま画面に返さない。
		if raw == "abc" && strings.Contains(w.Body.String(), "abc") {
			t.Error("the error page echoes the input")
		}
	}
	if got := storedAuthRate(t, f.vault.db, 1); got.Valid {
		t.Errorf("stored = %d, want NULL", got.Int64)
	}

	// 存在しない machine。
	if w := f.post(t, "/ui/machines/99/auth-rate", url.Values{"rate": {"20"}}); w.Code != http.StatusBadRequest {
		t.Errorf("unknown machine = %d, want 400", w.Code)
	}
	// セッションなしでは変えられない(他の POST と同じ網を通っている)。
	f.do(t, http.MethodPost, "/ui/machines/1/auth-rate", url.Values{"rate": {"20"}}, false)
	if got := storedAuthRate(t, f.vault.db, 1); got.Valid {
		t.Errorf("the auth rate was changed without a session: stored = %d", got.Int64)
	}
}

// 上限を設定していない machine は、既定値で数える(一覧にも既定値が出る)。
func TestMachineAuthRateDefaultsWhenUnset(t *testing.T) {
	t.Parallel()

	f := newRateFixture(t)
	db := f.store.DB()
	if rate, err := MachineAuthRate(t.Context(), db, f.clientID); err != nil || rate != authTokenRatePerClientID {
		t.Errorf("MachineAuthRate = %d, %v, want the default", rate, err)
	}
	if rate, err := MachineAuthRate(t.Context(), db, "no-such-client"); err != nil || rate != authTokenRatePerClientID {
		t.Errorf("MachineAuthRate for an unknown client id = %d, %v, want the default", rate, err)
	}
	machines, err := ListMachines(t.Context(), db)
	if err != nil || len(machines) != 1 || machines[0].AuthRate != authTokenRatePerClientID {
		t.Errorf("ListMachines = %+v, %v", machines, err)
	}
}

// ==== 別の担当が足したテスト(コミット前の手順 3) ====

// ---- 並行制御(ルール 68) ----

// rateChange は、machines.auth_rate_per_minute への UPDATE 1 回である
// (テスト用のトリガが、UPDATE と同じトランザクションで記録する)。
type rateChange struct {
	at       int64 // UPDATE が書いた updated_at(= 呼び出しの ac.Now)
	old, new sql.NullInt64
}

func rateChanges(t *testing.T, db *sql.DB) []rateChange {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), `SELECT at, old_rate, new_rate FROM rate_changes ORDER BY seq`)
	if err != nil {
		t.Fatalf("read rate_changes: %v", err)
	}
	defer rows.Close()

	var out []rateChange
	for rows.Next() {
		var c rateChange
		if err := rows.Scan(&c.at, &c.old, &c.new); err != nil {
			t.Fatalf("scan rate_changes: %v", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read rate_changes: %v", err)
	}
	return out
}

// **上げる操作は、どの順序で割り込まれても fail open の経路を通らない**(ルール 26 / 27 / 68)。
//
// 複数の goroutine が、同じ machine の上限を同時に上げ下げする。**どの順序で
// 実行されたかは見ない。** どの順序でも成り立つことだけを確かめる。
//
// 実際に起きた変更は、テスト用のトリガで別の表に写す(UPDATE と同じ
// トランザクションなので、順序も、巻き戻しも、本体と一致する)。呼び出しごとに
// ac.Now を変えてあるので、updated_at から「どの呼び出しの変更か」が分かり、
// 監査行(at)とも突き合わせられる。
//
// **最後の監査行の値が、保存された値と一致するとは限らない**ことに注意。
// 下げる操作の監査行は UPDATE の後に別の文で書くので、その間に別の変更と
// その監査行が入りうる。だから「最後の行 = いまの値」は検査しない。
//
// SQLITE_BUSY について: 書き込みは busy_timeout(5 秒)で待つので、通常は
// 出ない。それでも出たときに落ちるテストにはしない(負荷の高い CI で
// 確率的に落ちる)。BUSY で失敗した呼び出しは「何も変えていない」ことを確かめ、
// 下げる操作の監査行だけが欠けた場合は、運用ログの行数と突き合わせる。
func TestSetMachineAuthRateConcurrent(t *testing.T) {
	t.Parallel()

	const (
		initial    = 20
		goroutines = 8
	)
	// **各 goroutine が「最小 → 最大 → 最小」を含む。** 失敗が無ければ、どの順序でも
	// 上げる変更と下げる変更が少なくとも 1 回ずつ起きる(下の空振りの検査)。
	sequence := []int{authTokenRatePerClientID, authTokenRatePerIP, authTokenRatePerClientID, 25, 15, initial}

	for name, auditDown := range map[string]bool{"audit intact": false, "audit failing": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newRateFixture(t)
			db := f.store.DB()
			mustSetAuthRate(t, db, f.machineID, initial)

			for _, stmt := range []string{
				`CREATE TABLE rate_changes (
					seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, old_rate INTEGER, new_rate INTEGER)`,
				`CREATE TRIGGER log_rate_change AFTER UPDATE ON machines
				 BEGIN
					INSERT INTO rate_changes (at, old_rate, new_rate)
					VALUES (NEW.updated_at, OLD.auth_rate_per_minute, NEW.auth_rate_per_minute);
				 END`,
			} {
				if _, err := db.ExecContext(t.Context(), stmt); err != nil {
					t.Fatalf("set up the change log: %v", err)
				}
			}
			if auditDown {
				// 表は残し、INSERT だけを失敗させる(監査 DB の障害)。
				if _, err := db.ExecContext(t.Context(), `
					CREATE TRIGGER audit_down BEFORE INSERT ON audit_logs
					BEGIN SELECT RAISE(ABORT, 'audit write failed'); END`); err != nil {
					t.Fatalf("create trigger: %v", err)
				}
			}

			type call struct {
				rate int
				err  error
			}
			// キーは ac.Now(Unix 秒)。呼び出しごとに違う値にする。
			calls := make(map[int64]*call, goroutines*len(sequence))
			var (
				log   strings.Builder
				wg    sync.WaitGroup
				start = make(chan struct{})
			)
			logger := newTestLogger(&log)
			for g := range goroutines {
				mine := make([]*call, len(sequence))
				ats := make([]time.Time, len(sequence))
				for i := range sequence {
					// goroutine ごとに並びをずらす(全員が同じ値を同時に出すだけにしない)。
					mine[i] = &call{rate: sequence[(i+g)%len(sequence)]}
					ats[i] = vaultNow.Add(time.Duration(1+g*len(sequence)+i) * time.Second)
					calls[ats[i].Unix()] = mine[i]
				}
				wg.Go(func() {
					<-start
					for i, c := range mine {
						c.err = SetMachineAuthRate(t.Context(), db, logger, f.machineID, c.rate,
							auditCtx{Actor: ActorAnonymous, Now: ats[i]})
					}
				})
			}
			close(start)
			wg.Wait()

			// ---- 呼び出しの結果 ----
			var failed, busy int
			for at, c := range calls {
				if c.err == nil {
					continue
				}
				failed++
				switch {
				case strings.Contains(c.err.Error(), "SQLITE_BUSY"):
					busy++
				case auditDown && strings.Contains(c.err.Error(), "audit write failed"):
				default:
					t.Errorf("call at %d (rate %d): unexpected error: %v", at, c.rate, c.err)
				}
			}
			if busy > 0 {
				t.Logf("%d calls failed with SQLITE_BUSY (tolerated)", busy)
			}

			// ---- 実際に起きた変更 ----
			changes := rateChanges(t, db)
			var (
				raises, lowerings int
				changedAt         = map[int64]rateChange{}
				prev              = sql.NullInt64{Int64: initial, Valid: true}
			)
			for i, c := range changes {
				// 写しそのものの検査: 変更は 1 本の列になっている。
				if c.old != prev {
					t.Fatalf("change %d starts from %+v, but the previous change left %+v", i, c.old, prev)
				}
				prev = c.new

				from, to := authRateOf(c.old), authRateOf(c.new)
				who, ok := calls[c.at]
				switch {
				case !ok:
					t.Fatalf("change %d (%d -> %d) has updated_at = %d, which no call used", i, from, to, c.at)
				case who.err != nil:
					t.Errorf("change %d (%d -> %d): the call that made it returned an error: %v", i, from, to, who.err)
				case who.rate != to:
					t.Errorf("change %d set %d, but the call asked for %d", i, to, who.rate)
				}
				if _, dup := changedAt[c.at]; dup {
					t.Errorf("the call at %d changed the limit more than once", c.at)
				}
				changedAt[c.at] = c

				switch {
				case to > from:
					raises++
				case to < from:
					lowerings++
				default:
					t.Errorf("change %d wrote the limit that was already in effect (%d)", i, to)
				}
			}
			if got := storedAuthRate(t, db, f.machineID); got != prev {
				t.Errorf("stored = %+v, but the last change left %+v", got, prev)
			}
			final := authRateOf(prev)

			// ---- 監査行(at で呼び出しと対応する) ----
			audited := map[int64]int{}
			for _, s := range queryStrings(t, db, `
				SELECT at || ' ' || json_extract(detail, '$.rate') FROM audit_logs
				WHERE action = 'machine.set_auth_rate' ORDER BY id`) {
				atStr, rateStr, _ := strings.Cut(s, " ")
				at, err1 := strconv.ParseInt(atStr, 10, 64)
				rate, err2 := strconv.Atoi(rateStr)
				if err1 != nil || err2 != nil {
					t.Fatalf("audit row %q: %v, %v", s, err1, err2)
				}
				if at == vaultNow.Unix() {
					continue // 準備の mustSetAuthRate の行
				}
				// **変更していないのに、監査行だけが残ることは無い。**
				c, ok := changedAt[at]
				if !ok {
					t.Errorf("audit row (at %d, rate %d) has no change behind it", at, rate)
					continue
				}
				if want := authRateOf(c.new); rate != want {
					t.Errorf("audit row at %d has rate %d, but the change set %d", at, rate, want)
				}
				if audited[at]++; audited[at] > 1 {
					t.Errorf("the change at %d has more than one audit row", at)
				}
			}

			// **本題: 上げる変更は、必ず監査行を伴う。** 伴わない変更が 1 つでも
			// あれば、上げる操作が fail open の経路を通ったことになる。
			var unauditedLowerings int
			for at, c := range changedAt {
				if audited[at] == 1 {
					continue
				}
				if from, to := authRateOf(c.old), authRateOf(c.new); to > from {
					t.Errorf("the limit was raised %d -> %d (at %d) without an audit row", from, to, at)
				} else {
					unauditedLowerings++
				}
			}
			// 下げる変更の監査行が欠けてよいのは、書き込みに失敗して運用ログに
			// 出したときだけである(fail open)。黙って欠けることは無い。
			if logged := strings.Count(log.String(), "fail open"); logged != unauditedLowerings {
				t.Errorf("%d lowerings have no audit row, but the log reports %d failed audit writes\n%s",
					unauditedLowerings, logged, log.String())
			}

			if auditDown {
				// 監査が書けない間、上限は下がる一方である。
				if raises != 0 {
					t.Errorf("%d raises went through while the audit log could not be written", raises)
				}
				if final > initial {
					t.Errorf("the limit ended at %d, above the %d it started with", final, initial)
				}
				if len(audited) != 0 {
					t.Errorf("%d audit rows were written through a failing audit log", len(audited))
				}
				reachedMin := false
				for at, c := range calls {
					// 上限は initial を超えないので、それより大きい値の指定は必ず
					// 「上げる」になる。通ってはならない。
					if c.rate > initial && c.err == nil {
						t.Errorf("call at %d: raising to %d succeeded without an audit row", at, c.rate)
					}
					reachedMin = reachedMin || (c.rate == authTokenRatePerClientID && c.err == nil)
				}
				// 最小値への変更が 1 回でも成功すれば、その後は上がらないので、
				// 最後は最小値である(下げる操作は止まっていない)。
				if reachedMin && final != authTokenRatePerClientID {
					t.Errorf("a call lowered the limit to %d, but it ended at %d", authTokenRatePerClientID, final)
				}
				if busy == 0 && lowerings == 0 {
					t.Error("no lowering went through: lowering must not be stopped by the audit failure")
				}
				return
			}

			// 空振りの検査: 失敗が無ければ、上げる変更も下げる変更も起きている。
			if failed == 0 && (raises == 0 || lowerings == 0) {
				t.Errorf("%d raises and %d lowerings: the test did not exercise both directions", raises, lowerings)
			}
			if failed == 0 && unauditedLowerings != 0 {
				t.Errorf("%d lowerings have no audit row although nothing failed", unauditedLowerings)
			}
		})
	}
}

// ---- Machine API ----

// authChecked は authFrom と同じで、**Retry-After の不変条件を毎回確かめる**:
// 429 には 1 以上、窓の長さ以下の整数が付き、それ以外の応答には付かない。
func (f *apiFixture) authChecked(t *testing.T, clientID, secret, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()

	w := f.authFrom(t, clientID, secret, remoteAddr)
	checkRetryAfter(t, w)
	return w
}

func checkRetryAfter(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()

	values := w.Header().Values("Retry-After")
	if w.Code != http.StatusTooManyRequests {
		if len(values) != 0 {
			t.Errorf("status %d has Retry-After = %q, want none", w.Code, values)
		}
		return
	}
	if len(values) != 1 {
		t.Errorf("429 has %d Retry-After headers (%q), want 1", len(values), values)
		return
	}
	n, err := strconv.Atoi(values[0])
	if err != nil || strconv.Itoa(n) != values[0] || n < 1 || n > int(rateWindow/time.Second) {
		t.Errorf("Retry-After = %q, want an integer between 1 and %d", values[0], int(rateWindow/time.Second))
	}
}

// expectAuth は、同じ認証を n 回送り、全て want で返ることを確かめる。
func (f *apiFixture) expectAuth(t *testing.T, n int, clientID, secret, remoteAddr string, want int) {
	t.Helper()

	for i := range n {
		if w := f.authChecked(t, clientID, secret, remoteAddr); w.Code != want {
			t.Fatalf("%s from %s: attempt %d of %d = %d, want %d (body %q)",
				clientID, remoteAddr, i+1, n, w.Code, want, w.Body.String())
		}
	}
}

// **1 つの送信元からは、machine をいくつ置いても 1 分に 30 回までである**
// (ルール 35、DESIGN §7.4)。全ての machine の上限を最大にしても、合計は増えない。
func TestAPIAuthRateManyRaisedMachinesShareTheIPLimit(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	db := f.store.DB()
	type cred struct{ clientID, secret string }
	creds := []cred{{f.clientID, f.secret}}
	mustSetAuthRate(t, db, f.machineID, authTokenRatePerIP)
	for _, clientID := range []string{"app-batch", "app-cron"} {
		id, secret, err := CreateMachine(t.Context(), db, clientID, clientID,
			auditCtx{Actor: ActorAnonymous, Now: vaultNow})
		if err != nil {
			t.Fatalf("CreateMachine: %v", err)
		}
		mustSetAuthRate(t, db, id, authTokenRatePerIP)
		creds = append(creds, cred{clientID, secret})
	}

	// 3 台が 1 つの送信元から順に認証する。合計 30 回までは通る。
	const shared = "10.0.0.2:5000"
	for i := range authTokenRatePerIP {
		c := creds[i%len(creds)]
		f.expectAuth(t, 1, c.clientID, c.secret, shared, http.StatusOK)
	}
	// 31 回目は、どの machine でも第一段で弾かれる(どれも自分の上限には届いていない)。
	// **第一段の拒否は監査に残さない**(送信元を変えるだけで監査 DB を膨らませない)。
	before := countAuditLogs(t, db, ActionAuthMachine)
	for _, c := range creds {
		f.expectAuth(t, 1, c.clientID, c.secret, shared, http.StatusTooManyRequests)
	}
	if after := countAuditLogs(t, db, ActionAuthMachine); after != before {
		t.Errorf("auth.machine rows went from %d to %d: a first-stage rejection was recorded", before, after)
	}

	// 第二段は client_id ごとに数えている: 別の送信元からなら、残りの 20 回が通る。
	// 弾かれた試行は数えない。
	used := authTokenRatePerIP / len(creds)
	f.expectAuth(t, authTokenRatePerIP-used, f.clientID, f.secret, "10.0.0.3:5000", http.StatusOK)
	f.expectAuth(t, 1, f.clientID, f.secret, "10.0.0.4:5000", http.StatusTooManyRequests)
	// 第二段の拒否は監査に残す。
	if after := countAuditLogs(t, db, ActionAuthMachine); after != before+authTokenRatePerIP-used+1 {
		t.Errorf("auth.machine rows = %d, want %d (the second-stage rejection is recorded)",
			after, before+authTokenRatePerIP-used+1)
	}
}

// **sealed 中も、上限は machine の設定から引く**(DESIGN §7.4)。上げた machine は、
// 上げた回数まで 503 を受け取ってから 429 になる。503 に Retry-After は付かない。
func TestAPIAuthRateWhileSealed(t *testing.T) {
	t.Parallel()

	v := newSealedVault(t)
	f := &apiFixture{api: newMachineAPI(v, discardLogger()), vault: v}
	f.api.now = func() time.Time { return vaultNow }

	secrets := map[string]string{}
	for clientID, rate := range map[string]int{"raised": 20, "default": authTokenRatePerClientID} {
		id, secret, err := CreateMachine(t.Context(), v.db, clientID, clientID,
			auditCtx{Actor: ActorAnonymous, Now: vaultNow})
		if err != nil {
			t.Fatalf("CreateMachine: %v", err)
		}
		mustSetAuthRate(t, v.db, id, rate)
		secrets[clientID] = secret
	}

	f.expectAuth(t, 20, "raised", secrets["raised"], "10.0.0.2:5000", http.StatusServiceUnavailable)
	f.expectAuth(t, 1, "raised", secrets["raised"], "10.0.0.2:5000", http.StatusTooManyRequests)

	f.expectAuth(t, authTokenRatePerClientID, "default", secrets["default"], "10.0.0.3:5000", http.StatusServiceUnavailable)
	f.expectAuth(t, 1, "default", secrets["default"], "10.0.0.3:5000", http.StatusTooManyRequests)
}

// **無効にした machine は、設定された上限のまま数える。応答は 401 のままである。**
//
// 上限を上げてあることは、有効な machine でも secret なしで観測できる
// (受容済み。THREAT_MODEL N7)。無効な machine で応答の種類が変わると、
// 「無効になった」という別の情報が漏れる。
func TestAPIAuthRateForDisabledMachine(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	const raised = 20
	mustSetAuthRate(t, f.store.DB(), f.machineID, raised)
	if err := DisableMachine(t.Context(), f.vault, f.machineID,
		auditCtx{Actor: ActorAnonymous, Now: vaultNow}); err != nil {
		t.Fatalf("DisableMachine: %v", err)
	}

	// 存在しない client_id の応答と、区別がつかない。
	unknown := f.authChecked(t, "no-such-client", "x", "10.0.9.9:5000")
	if unknown.Code != http.StatusUnauthorized {
		t.Fatalf("unknown client id = %d, want 401", unknown.Code)
	}
	for i := range raised {
		// 正しい secret でも 401。
		w := f.authChecked(t, f.clientID, f.secret, "10.0.0.2:5000")
		if w.Code != http.StatusUnauthorized || w.Body.String() != unknown.Body.String() {
			t.Fatalf("attempt %d = %d %q, want the same 401 as an unknown client id (%q)",
				i+1, w.Code, w.Body.String(), unknown.Body.String())
		}
	}
	f.expectAuth(t, 1, f.clientID, f.secret, "10.0.0.2:5000", http.StatusTooManyRequests)

	// 無効にした後も、上限は下げられる(制限を強める操作は止めない)。
	mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerClientID)
	if got := storedAuthRate(t, f.store.DB(), f.machineID); got.Valid {
		t.Errorf("stored = %d after resetting a disabled machine, want NULL", got.Int64)
	}
}

// **上限を引けなかったときは、既定値(一番厳しい値)で数える。** 上げた machine でも、
// 引けなかったリクエストが、上げた上限で通ることは無い。
func TestMachineAuthRateFallsBackToTheDefaultOnError(t *testing.T) {
	t.Parallel()

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()

		f := newRateFixture(t)
		mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerIP)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		rate, err := MachineAuthRate(ctx, f.store.DB(), f.clientID)
		if err == nil || rate != authTokenRatePerClientID {
			t.Errorf("MachineAuthRate = %d, %v, want the default and an error", rate, err)
		}
	})

	t.Run("closed database", func(t *testing.T) {
		t.Parallel()

		f := newRateFixture(t)
		mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerIP)
		if err := f.store.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		rate, err := MachineAuthRate(t.Context(), f.store.DB(), f.clientID)
		if err == nil || rate != authTokenRatePerClientID {
			t.Errorf("MachineAuthRate = %d, %v, want the default and an error", rate, err)
		}
	})
}

// 同じことを、ハンドラを通して確かめる。**取り消されたリクエスト(DB を読めない)は
// 既定値で数えられ、1 回も認証を通さない。** 数えた回数は、その後の正常な
// リクエストにも持ち越す(取り消しを挟んでも、上げた上限を超えては試せない)。
func TestAPIAuthRateLookupFailureUsesTheDefault(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	mustSetAuthRate(t, f.store.DB(), f.machineID, authTokenRatePerIP)

	cancelled := func(remoteAddr string) *httptest.ResponseRecorder {
		t.Helper()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var body any = authTokenRequest{ClientID: f.clientID, ClientSecret: f.secret}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/auth/token", bytes.NewReader(encoded))
		r.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		f.api.machineMux().ServeHTTP(w, r)
		checkRetryAfter(t, w)
		return w
	}

	tokens := countAuditLogs(t, f.store.DB(), ActionAuthMachine)
	for i := range authTokenRatePerClientID {
		// 正しい secret だが、DB を読めないので通らない。
		if w := cancelled("10.0.0.2:5000"); w.Code == http.StatusOK || w.Code == http.StatusTooManyRequests {
			t.Fatalf("cancelled attempt %d = %d, want a failure other than 429", i+1, w.Code)
		}
	}
	// 既定値の回数を使い切った。上げた上限(30)では数えていない。
	if w := cancelled("10.0.0.2:5000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("cancelled attempt %d = %d, want 429 from the default limit", authTokenRatePerClientID+1, w.Code)
	}
	if got := countAuditLogs(t, f.store.DB(), ActionAuthMachine); got != tokens {
		t.Errorf("auth.machine rows went from %d to %d through cancelled requests", tokens, got)
	}

	// 上限を引けるリクエストは、上げた上限で数える。取り消されたリクエストの
	// 10 回は持ち越すので、通るのは残りの 20 回である(送信元は分ける)。
	f.expectAuth(t, authTokenRatePerIP-authTokenRatePerClientID, f.clientID, f.secret, "10.0.0.3:5000", http.StatusOK)
	f.expectAuth(t, 1, f.clientID, f.secret, "10.0.0.4:5000", http.StatusTooManyRequests)
}

// **窓の途中で上げた上限は、その窓の残りに効く**(数えた回数は持ち越す)。
// 窓が明ければ数え直す。途中で下げたときの Retry-After は、窓の残りである。
func TestAPIAuthRateChangesWithinAWindow(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	db := f.store.DB()
	now := vaultNow
	f.api.now = func() time.Time { return now }
	const addr = "10.0.0.2:5000"
	rejected := func(wantRetryAfter string) {
		t.Helper()

		w := f.authChecked(t, f.clientID, f.secret, addr)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", w.Code)
		}
		if got := w.Header().Get("Retry-After"); got != wantRetryAfter {
			t.Errorf("Retry-After = %q, want %s", got, wantRetryAfter)
		}
	}

	// 既定値を使い切る。
	f.expectAuth(t, authTokenRatePerClientID, f.clientID, f.secret, addr, http.StatusOK)
	rejected("60")

	// 20 秒後に 15 へ上げる。通るのは差の 5 回だけ(弾かれた試行は数えていない)。
	now = vaultNow.Add(20 * time.Second)
	mustSetAuthRate(t, db, f.machineID, 15)
	f.expectAuth(t, 15-authTokenRatePerClientID, f.clientID, f.secret, addr, http.StatusOK)
	rejected("40")

	// 窓が明けたら数え直す。上げた上限は残っている。
	now = vaultNow.Add(rateWindow + time.Second)
	f.expectAuth(t, 15, f.clientID, f.secret, addr, http.StatusOK)
	rejected("60")

	// 新しい窓が開いて 30 秒後に既定値へ戻す。15 回数えてあるので、すぐ弾かれる。
	// 待ち時間は、下げた時刻からではなく、窓の残りである。
	now = now.Add(30 * time.Second)
	mustSetAuthRate(t, db, f.machineID, authTokenRatePerClientID)
	rejected("30")

	// その窓が明ければ、既定値で数え直す。
	now = now.Add(30 * time.Second)
	f.expectAuth(t, authTokenRatePerClientID, f.clientID, f.secret, addr, http.StatusOK)
	rejected("60")
}

// ---- 監査 ----

// **machine.set_auth_rate は人の操作であり、刈り込みで消えない**(ルール 28)。
// 対象の条件は allowlist なので、実行者が machine の行であっても消えない。
func TestPruneAuditLogsKeepsSetAuthRateRows(t *testing.T) {
	t.Parallel()

	s := newAuditSeed(t)
	old := daysAgo(200)
	for i, ac := range []auditCtx{
		s.userAudit(old), // 上げる(同じトランザクションで書く行)
		s.userAudit(old), // 下げる(後から書く行)
		// 実際には起きない組み合わせ(machine は自分の上限を変えられない)。
		// それでも、操作が allowlist に無いので消えない。
		machineAudit(s.machineID, "10.0.0.2", old),
	} {
		if err := SetMachineAuthRate(t.Context(), s.db, discardLogger(), s.machineID, []int{25, 15, 20}[i], ac); err != nil {
			t.Fatalf("SetMachineAuthRate: %v", err)
		}
	}
	// 比較のため、消える行を 1 つ置く(刈り込みが空振りしていないことの確認)。
	mustRecord(t, s.db, machineAudit(s.machineID, "10.0.0.2", old).machineEntry(ActionAuthMachine, s.machineID))

	if n := mustPrune(t, s.db, 100); n != 1 {
		t.Errorf("pruned %d rows, want 1 (only the machine's successful auth)", n)
	}
	if n := countAuditLogs(t, s.db, ActionMachineSetAuthRate); n != 3 {
		t.Errorf("%d machine.set_auth_rate rows are left, want 3", n)
	}
	if n := countAuditLogs(t, s.db, ActionAuthMachine); n != 0 {
		t.Errorf("%d auth.machine rows are left, want 0", n)
	}
}

// ---- Web UI ----

// uiAuditRows は、操作 1 種類の監査行を
// 「actor|actor_user_id|target_machine_id|result|remote_addr|via」の形で返す。
func uiAuditRows(t *testing.T, db *sql.DB, action Action) []string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), `
		SELECT actor || '|' || COALESCE(actor_user_id, '') || '|' || COALESCE(target_machine_id, '')
			|| '|' || result || '|' || COALESCE(remote_addr, '') || '|' || COALESCE(json_extract(detail, '$.via'), '')
		FROM audit_logs WHERE action = ? ORDER BY id`, string(action))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("query: %v", err)
	}
	return out
}

// **画面からの変更は、誰が・どこから・どの machine を、を他の操作と同じ形で残す。**
// 上げる行(同じトランザクションで書く)と下げる行(後から書く)は経路が違うので、
// 両方を見る。
func TestUISetMachineAuthRateAuditRow(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}
	for _, rate := range []string{"25", "15"} {
		w := f.post(t, "/ui/machines/1/auth-rate", url.Values{"rate": {rate}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("set auth rate %s = %d (body %q)", rate, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Location"); got != "/ui/machines" {
			t.Errorf("Location = %q, want /ui/machines", got)
		}
	}
	if w := f.post(t, "/ui/machines/1/disable", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("disable = %d", w.Code)
	}

	// 画面の操作は remote_addr を持たず、detail.via が web である(uiRequest.auditCtx)。
	// **detail.rate を入れるときに、via を落とさない**(detail を丸ごと置き換えると消える)。
	want := fmt.Sprintf("user:%d|%d|1|success||%s", f.userID, f.userID, ViaWeb)
	// まず、同じ画面の別の操作(無効化)がこの形であることを確かめる(比較の基準)。
	if other := uiAuditRows(t, f.vault.db, ActionMachineDisable); len(other) != 1 || other[0] != want {
		t.Fatalf("test setup: machine.disable row = %q, want %q", other, want)
	}
	got := uiAuditRows(t, f.vault.db, ActionMachineSetAuthRate)
	if len(got) != 2 || got[0] != want || got[1] != want {
		t.Errorf("machine.set_auth_rate rows = %q, want two of %q (the same shape as machine.disable)", got, want)
	}
	rates := queryStrings(t, f.vault.db, `
		SELECT json_extract(detail, '$.rate') FROM audit_logs WHERE action = 'machine.set_auth_rate' ORDER BY id`)
	if strings.Join(rates, ",") != "25,15" {
		t.Errorf("detail.rate = %v, want [25 15]", rates)
	}
	// 入力した文字列や client_id は、行に入らない(target は immutable な ID だけ)。
	if targets := queryStrings(t, f.vault.db, `
		SELECT COALESCE(target, '') FROM audit_logs WHERE action = 'machine.set_auth_rate'`); strings.Join(targets, "") != "" {
		t.Errorf("target = %q, want empty", targets)
	}
}

// **CSRF トークンが無い変更は通らない。**(TestUIPostsRequireCSRF の一覧は
// 手で足すものなので、このルートはここで固定する。)
func TestUISetMachineAuthRateRequiresCSRF(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}

	other := newTestSession(t, f.store, f.userID)
	for name, form := range map[string]url.Values{
		"no token":                {"rate": {"20"}},
		"empty token":             {"rate": {"20"}, "csrf_token": {""}},
		"another session's token": {"rate": {"20"}, "csrf_token": {csrfToken(other)}},
	} {
		if w := f.do(t, http.MethodPost, "/ui/machines/1/auth-rate", form, true); w.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", name, w.Code)
		}
	}
	if got := storedAuthRate(t, f.vault.db, 1); got.Valid {
		t.Errorf("the auth rate was changed without a csrf token: stored = %d", got.Int64)
	}
	if n := countAuditLogs(t, f.vault.db, ActionMachineSetAuthRate); n != 0 {
		t.Errorf("%d machine.set_auth_rate rows for rejected requests, want 0", n)
	}
	if n := countAuditLogs(t, f.vault.db, ActionCSRFReject); n != 3 {
		t.Errorf("%d csrf.reject rows, want 3", n)
	}
}

// sealed 中は、他の machine の操作と同じく unseal へ送られ、何も変わらない。
func TestUISetMachineAuthRateWhileSealed(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t) // sealed のまま
	id, _, err := CreateMachine(t.Context(), f.vault.db, "app-prod", "app", f.auditCtx())
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}

	w := f.post(t, fmt.Sprintf("/ui/machines/%d/auth-rate", id), url.Values{"rate": {"20"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/unseal" {
		t.Errorf("while sealed = %d %q, want a redirect to /ui/unseal", w.Code, w.Header().Get("Location"))
	}
	if got := storedAuthRate(t, f.vault.db, id); got.Valid {
		t.Errorf("the auth rate was changed while sealed: stored = %d", got.Int64)
	}
	if n := countAuditLogs(t, f.vault.db, ActionMachineSetAuthRate); n != 0 {
		t.Errorf("%d machine.set_auth_rate rows, want 0", n)
	}
}

// **無効な machine にも、上限のフォームは出る。** 無効化と再発行のボタンは
// 消えるが、上限は「下げる」操作でもあるので、画面から届かなくしない。
// 範囲の説明は、定数から出す。
func TestUIMachineAuthRateFormForDisabledMachine(t *testing.T) {
	t.Parallel()

	f := newUIFixture(t)
	f.unseal(t)
	if w := f.post(t, "/ui/machines", url.Values{"name": {"app"}}); w.Code != http.StatusOK {
		t.Fatalf("create machine = %d", w.Code)
	}

	// machine が無いときも、範囲の説明は出る。
	wantHint := fmt.Sprintf("%d 以上 %d 以下。既定は %d", authTokenRatePerClientID, authTokenRatePerIP, authTokenRatePerClientID)
	if body := f.get(t, "/ui/machines").Body.String(); !strings.Contains(body, wantHint) {
		t.Errorf("the machine page does not explain the range (want %q)", wantHint)
	}

	if w := f.post(t, "/ui/machines/1/auth-rate", url.Values{"rate": {"25"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("set auth rate = %d", w.Code)
	}
	if w := f.post(t, "/ui/machines/1/disable", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("disable = %d", w.Code)
	}

	body := f.get(t, "/ui/machines").Body.String()
	if strings.Contains(body, `action="/ui/machines/1/disable"`) {
		t.Fatal("test setup: the machine is not shown as disabled")
	}
	wantInput := fmt.Sprintf(`name="rate" value="25" min="%d" max="%d" step="1" required`,
		authTokenRatePerClientID, authTokenRatePerIP)
	if !strings.Contains(body, `action="/ui/machines/1/auth-rate"`) || !strings.Contains(body, wantInput) {
		t.Errorf("a disabled machine has no form for the auth rate (want %s)", wantInput)
	}
	// フォームは 1 台に 1 つで、CSRF トークンを持つ。
	_, form, _ := strings.Cut(body, `action="/ui/machines/1/auth-rate"`)
	form, _, _ = strings.Cut(form, "</form>")
	if strings.Count(body, `/auth-rate"`) != 1 || !strings.Contains(form, f.csrf) {
		t.Error("the auth rate form is duplicated or has no csrf token")
	}

	// 無効な machine でも、既定値に戻せる。
	reset := url.Values{"rate": {strconv.Itoa(authTokenRatePerClientID)}}
	if w := f.post(t, "/ui/machines/1/auth-rate", reset); w.Code != http.StatusSeeOther {
		t.Fatalf("reset the auth rate of a disabled machine = %d (body %q)", w.Code, w.Body.String())
	}
	if got := storedAuthRate(t, f.vault.db, 1); got.Valid {
		t.Errorf("stored = %d, want NULL", got.Int64)
	}
}

// 範囲の外の値が保存されていても、一覧に出るのは実際に効いている上限である
// (フォームの初期値が min / max の外に出ると、何も変えずに送信できなくなる)。
func TestListMachinesShowsTheEffectiveAuthRate(t *testing.T) {
	t.Parallel()

	f := newRateFixture(t)
	db := f.store.DB()
	for stored, want := range map[int64]int{5: authTokenRatePerClientID, 22: 22, 99: authTokenRatePerIP} {
		if _, err := db.ExecContext(t.Context(),
			`UPDATE machines SET auth_rate_per_minute = ? WHERE id = ?`, stored, f.machineID); err != nil {
			t.Fatalf("store %d: %v", stored, err)
		}
		machines, err := ListMachines(t.Context(), db)
		if err != nil || len(machines) != 1 || machines[0].AuthRate != want {
			t.Errorf("stored %d: ListMachines = %+v, %v, want AuthRate %d", stored, machines, err, want)
		}
	}
}

func TestParseCanonicalInt(t *testing.T) {
	t.Parallel()

	accepted := map[string]int{
		"0": 0, "7": 7, "10": 10, "30": 30, "-5": -5,
		"9223372036854775807": 9223372036854775807,
	}
	for s, want := range accepted {
		if got, ok := parseCanonicalInt(s); !ok || got != want {
			t.Errorf("parseCanonicalInt(%q) = %d, %v, want %d, true", s, got, ok, want)
		}
	}
	// 同じ数を表す別の書き方と、数でないもの。
	for _, s := range []string{
		"", " ", "+5", "05", "00", "-0", "+0", " 5", "5 ", "5\n", "\t5", "5.0", "5.", "1e1", "0x10", "0b1", "1_000",
		"５", "٥", "--5", "5-", "abc", "5a", "9223372036854775808", "-9223372036854775809",
	} {
		if got, ok := parseCanonicalInt(s); ok {
			t.Errorf("parseCanonicalInt(%q) = %d, true, want false", s, got)
		}
	}
}

// ---- 移行 ----

// **v3 の DB を v4 にしても、既にある machine の行は変わらず、上限は未設定
// (NULL = 既定値)になる。** grant も残る(表を作り直していない)。
func TestMigrateV3ToV4KeepsMachines(t *testing.T) {
	t.Parallel()

	store, err := openDatabase(t.Context(), t.TempDir()+"/hokora.db")
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	db := store.DB()
	if err := migrate(t.Context(), db, migrations[:3]); err != nil {
		t.Fatalf("migrate to v3: %v", err)
	}

	// v3 の列だけで書く(有効、無効、認証済み、未認証)。
	for _, stmt := range []string{
		`INSERT INTO machines (client_id, secret_hash, name, disabled, created_at, updated_at, last_auth_at)
		 VALUES ('app-prod', x'0102', 'web01', 0, 100, 200, 300)`,
		`INSERT INTO machines (client_id, secret_hash, name, disabled, created_at, updated_at, last_auth_at)
		 VALUES ('app-old', x'0304', 'retired', 1, 110, 210, NULL)`,
	} {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("insert machine: %v", err)
		}
	}
	envID := insertEnvironment(t, db, insertProject(t, db, "myapp", false), "prod", false)
	if _, err := db.ExecContext(t.Context(),
		`INSERT INTO machine_grants (machine_id, environment_id, created_at) VALUES (1, ?, 100)`, envID); err != nil {
		t.Fatalf("insert grant: %v", err)
	}

	const snapshot = `
		SELECT id || '|' || client_id || '|' || hex(secret_hash) || '|' || name || '|' || disabled
			|| '|' || created_at || '|' || updated_at || '|' || COALESCE(last_auth_at, 'NULL')
		FROM machines ORDER BY id`
	before := queryStrings(t, db, snapshot)
	if len(before) != 2 {
		t.Fatalf("test setup: %d machines, want 2", len(before))
	}

	if err := migrate(t.Context(), db, migrations[:4]); err != nil {
		t.Fatalf("migrate to v4: %v", err)
	}
	if version, err := schemaVersionOf(t.Context(), db); err != nil || version != 4 {
		t.Fatalf("schema version = %d, %v, want 4", version, err)
	}

	if after := queryStrings(t, db, snapshot); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Errorf("machines changed:\n%s\nwant:\n%s", strings.Join(after, "\n"), strings.Join(before, "\n"))
	}
	if set := queryStrings(t, db,
		`SELECT client_id FROM machines WHERE auth_rate_per_minute IS NOT NULL`); len(set) != 0 {
		t.Errorf("machines %v got an auth rate from the migration, want NULL for all", set)
	}
	if grants := queryStrings(t, db, `SELECT machine_id || '/' || environment_id FROM machine_grants`); len(grants) != 1 {
		t.Errorf("grants = %v, want 1", grants)
	}

	// 移行した DB で、読み書きが新しい DB と同じように動く。
	for _, clientID := range []string{"app-prod", "app-old"} {
		if rate, err := MachineAuthRate(t.Context(), db, clientID); err != nil || rate != authTokenRatePerClientID {
			t.Errorf("%s: MachineAuthRate = %d, %v, want the default", clientID, rate, err)
		}
	}
	mustSetAuthRate(t, db, 1, 20)
	if got := storedAuthRate(t, db, 1); !got.Valid || got.Int64 != 20 {
		t.Errorf("stored = %+v after raising on a migrated database, want 20", got)
	}
	if got := storedAuthRate(t, db, 2); got.Valid {
		t.Errorf("the other machine got %d, want NULL", got.Int64)
	}
	// スキーマの検査も付いている。
	if _, err := db.ExecContext(t.Context(), `UPDATE machines SET auth_rate_per_minute = 0 WHERE id = 1`); err == nil {
		t.Error("the migrated schema accepted auth_rate_per_minute = 0")
	}
}
