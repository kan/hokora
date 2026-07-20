package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 本ファイルは DESIGN §4.4 の C1〜C10 を検証する。
//
// **go test -race ではこれらの違反を検出できない。** race detector が見るのは
// 「同じメモリへの同期されないアクセス」であって、「seal 後に有効なトークンが
// 残っている」のような意味上の競合は見えない(AGENTS.md ルール 68)。

// issueTestToken は verify が常に成功するトークン発行である。
func issueTestToken(v *Vault, machineID int64, now time.Time) (string, error) {
	encoded, _, err := v.IssueToken(now, func() (int64, error) { return machineID, nil })
	return encoded, err
}

// decodeToken は発行された base64url トークンを生バイト列へ戻す。
func decodeToken(t *testing.T, encoded string) []byte {
	t.Helper()

	raw, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	return raw
}

// C6: トークン発行と seal を並行実行し、**seal 後に有効なトークンが 1 つも
// 存在しない**ことを確認する。
//
// 発行処理が read lock 内で完結していないと、次の並びで seal をすり抜ける:
//
//	auth:  unsealed を確認
//	seal:                write lock、token store を clear、sealed へ
//	auth:  token を store に追加   ← 生き残る
func TestVaultC6IssueTokenDoesNotEscapeSeal(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)

	const rounds = 3
	const issuers = 32

	for round := range rounds {
		unsealForTest(t, v, mk)

		var (
			wg     sync.WaitGroup
			mu     sync.Mutex
			issued []string
			start  = make(chan struct{})
		)
		for i := range issuers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				encoded, err := issueTestToken(v, int64(i%4)+1, vaultNow)
				switch {
				case err == nil:
					mu.Lock()
					issued = append(issued, encoded)
					mu.Unlock()
				case errors.Is(err, ErrSealed):
					// seal が先に確定した。正常。
				default:
					t.Errorf("IssueToken: %v", err)
				}
			}()
		}

		sealDone := make(chan struct{})
		go func() {
			defer close(sealDone)
			<-start
			v.Seal(t.Context(), socketAudit(vaultNow))
		}()

		close(start)
		wg.Wait()
		<-sealDone

		if got := v.Status(); got.State != StateSealed {
			t.Fatalf("round %d: state = %v, want sealed", round, got.State)
		}
		if got := v.Status().Tokens; got != 0 {
			t.Fatalf("round %d: %d tokens survived seal", round, got)
		}
		for _, encoded := range issued {
			if _, ok := v.LookupToken(decodeToken(t, encoded), vaultNow); ok {
				t.Fatalf("round %d: a token issued around seal is still valid", round)
			}
		}
	}
}

// C2 / C3: Seal() は進行中の暗号操作の完了を待つ。
// 待たなければ、WithDEK の中でゼロクリア済みの DEK を読むことになる。
func TestVaultC2SealWaitsForInFlightCryptoOperations(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	var (
		inside     = make(chan struct{})
		release    = make(chan struct{})
		sealed     atomic.Bool
		dekIsZero  atomic.Bool
		cryptoDone = make(chan struct{})
	)

	go func() {
		defer close(cryptoDone)
		err := v.WithDEK(func(dek []byte, _ int64) error {
			close(inside)
			<-release
			// ここまで来ても seal は完了していないはずである(C2)。
			if sealed.Load() {
				t.Error("Seal completed while a crypto operation was still running")
			}
			// DEK もまだ生きているはずである(C3)。
			var zero bool
			for _, b := range dek {
				zero = zero || b != 0
			}
			dekIsZero.Store(!zero)
			return nil
		})
		if err != nil {
			t.Errorf("WithDEK: %v", err)
		}
	}()

	<-inside

	sealDone := make(chan struct{})
	go func() {
		defer close(sealDone)
		v.Seal(t.Context(), socketAudit(vaultNow))
		sealed.Store(true)
	}()

	// Seal が待っていることを確認する。ここで完了してしまうなら C2 違反。
	select {
	case <-sealDone:
		t.Fatal("Seal returned while a crypto operation was in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-cryptoDone
	<-sealDone

	if dekIsZero.Load() {
		t.Error("the dek was zeroed while a crypto operation was using it")
	}
	if got := v.Status(); got.State != StateSealed {
		t.Errorf("state = %v, want sealed", got.State)
	}
}

// seal → unseal を経ると、**旧トークンは無効である**。
// token store はメモリ上にしかないので、seal で消えたものは戻らない。
func TestVaultTokensDoNotSurviveSealUnsealCycle(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	encoded, err := issueTestToken(v, 1, vaultNow)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	raw := decodeToken(t, encoded)
	if _, ok := v.LookupToken(raw, vaultNow); !ok {
		t.Fatal("a freshly issued token is not valid")
	}

	v.Seal(t.Context(), socketAudit(vaultNow))
	if _, ok := v.LookupToken(raw, vaultNow); ok {
		t.Fatal("a token survived seal")
	}

	unsealForTest(t, v, mk)
	if _, ok := v.LookupToken(raw, vaultNow); ok {
		t.Fatal("a token from before seal became valid again after unseal")
	}
}

// C8: credential 失効(DB 更新 → トークン削除)を write lock 内で行うと、
// **旧 credential で進行中だった発行がすり抜けない**。
//
// これは C6 と同型の競合である。塞がないと、rotate_secret の完了後も旧
// credential 由来のトークンが最大 15 分生き残る。
func TestVaultC8RevocationDoesNotRaceTokenIssuance(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)

	const rounds = 3
	const issuers = 32
	const machineID = int64(1)

	for round := range rounds {
		unsealForTest(t, v, mk)

		// revoked は「DB 上の secret_hash が差し替わったか」を模したものである。
		// 発行側は verify の中でこれを読む(実装では DB を読む)。
		var revoked atomic.Bool

		var (
			wg     sync.WaitGroup
			mu     sync.Mutex
			issued []string
			start  = make(chan struct{})
		)
		for range issuers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				encoded, _, err := v.IssueToken(vaultNow, func() (int64, error) {
					if revoked.Load() {
						return 0, errors.New("invalid credentials")
					}
					return machineID, nil
				})
				switch {
				case err == nil:
					mu.Lock()
					issued = append(issued, encoded)
					mu.Unlock()
				case errors.Is(err, ErrSealed):
					t.Error("the vault was sealed unexpectedly")
				default:
					// 失効後の発行試行。正常。
				}
			}()
		}

		revokeDone := make(chan struct{})
		go func() {
			defer close(revokeDone)
			<-start
			err := v.WithWriteLock(func(tokens *tokenStore) error {
				// 実装では「DB tx commit → DeleteByMachine」の順になる。
				revoked.Store(true)
				tokens.DeleteByMachine(machineID)
				return nil
			})
			if err != nil {
				t.Errorf("WithWriteLock: %v", err)
			}
		}()

		close(start)
		wg.Wait()
		<-revokeDone

		// 失効前に発行されたトークンは、失効の完了時点で全て消えている。
		for _, encoded := range issued {
			if _, ok := v.LookupToken(decodeToken(t, encoded), vaultNow); ok {
				t.Fatalf("round %d: a token issued with the revoked credential is still valid", round)
			}
		}
		v.Seal(t.Context(), socketAudit(vaultNow))
	}
}

// C10: rotate-master を並行実行しても直列化される。
//
// 直列化されていないと、両方が旧 keyring を読んで検証に成功し、最後に commit
// した方の MK だけが有効になる。**どちらの MK が有効か分からない状態**が
// 生まれ、運用上の認識が壊れる。
func TestVaultC10RotateMasterIsSerialized(t *testing.T) {
	t.Parallel()

	v, store, oldMK := newTestVault(t)

	const rotations = 3
	newKeys := make([][]byte, rotations)
	for i := range newKeys {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		newKeys[i] = key
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded [][]byte
		start     = make(chan struct{})
	)
	for _, newMK := range newKeys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch err := v.RotateMaster(t.Context(), oldMK, newMK, socketAudit(vaultNow)); {
			case err == nil:
				mu.Lock()
				succeeded = append(succeeded, newMK)
				mu.Unlock()
			case errors.Is(err, ErrDecrypt):
				// 先に別の rotate が確定し、旧 MK が無効になった。正常。
			default:
				t.Errorf("RotateMaster: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	// 直列化されていれば、旧 MK で始められるのは最初の 1 つだけである。
	if len(succeeded) != 1 {
		t.Fatalf("%d concurrent rotations succeeded from the same current key, want 1", len(succeeded))
	}

	kr, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	dek, err := kr.UnwrapDEK(succeeded[0])
	if err != nil {
		t.Fatalf("the keyring cannot be opened with the master key that reported success: %v", err)
	}
	Zero(dek)

	if n := countAuditLogs(t, store.DB(), ActionMasterRotate); n != 1 {
		t.Errorf("%d master.rotate audit rows, want 1", n)
	}
}

// C7: ロックの取得順序は Vault.mu → tokenStore.mu で固定されている。
//
// 逆順が混ざるとデッドロックしうるので、全種類の操作を並行に回して詰まらない
// ことを確認する。**tokenStore が Vault を参照していないこと**が、この順序を
// 構造的に保証している(token.go のコメント参照)。
func TestVaultC7NoDeadlockUnderMixedOperations(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	done := make(chan struct{})
	var wg sync.WaitGroup

	worker := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					fn()
				}
			}
		}()
	}

	worker(func() { _, _ = issueTestToken(v, 1, vaultNow) })
	worker(func() { v.Status() })
	worker(func() { v.SweepTokens(vaultNow) })
	worker(func() { _ = v.WithDEK(func([]byte, int64) error { return nil }) })
	worker(func() {
		_ = v.WithWriteLock(func(tokens *tokenStore) error {
			tokens.DeleteByMachine(1)
			return nil
		})
	})
	worker(func() { _, _ = v.LookupToken(make([]byte, TokenBytes), vaultNow) })

	time.Sleep(100 * time.Millisecond)
	close(done)

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("mixed concurrent operations deadlocked")
	}
}

// トークンの期限は Vault 経由でも Lookup 時に検査される(sweep に依存しない)。
func TestVaultLookupTokenChecksExpiry(t *testing.T) {
	t.Parallel()

	v, _, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	encoded, expiresAt, err := v.IssueToken(vaultNow, func() (int64, error) { return 5, nil })
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if want := vaultNow.Add(TokenTTL); !expiresAt.Equal(want) {
		t.Errorf("expires at %v, want %v", expiresAt, want)
	}

	raw := decodeToken(t, encoded)
	if id, ok := v.LookupToken(raw, expiresAt.Add(-time.Nanosecond)); !ok || id != 5 {
		t.Errorf("Lookup before expiry = (%d, %v), want (5, true)", id, ok)
	}
	// sweep は一度も呼んでいない。それでも期限切れは弾かれる。
	if _, ok := v.LookupToken(raw, expiresAt); ok {
		t.Error("an expired token was accepted (expiry must not depend on sweep)")
	}
}

// C8 の実配線版: **実際の credential 検証と rotate_secret / disable を並行実行する。**
//
// vault_concurrency_test.go の TestVaultC8... は Vault のロック構造だけを見る
// モックだった。こちらは auth.go の DisableMachine / RotateMachineSecret を
// 通し、**旧 credential で得たトークンが失効後に 1 つも残らない**ことを見る。
//
// rotate_secret は「漏洩したから回す」操作である。まさに攻撃者が旧 credential
// を持っている状況で実行されるため、すり抜けは緩和策そのものを破る。
func TestC8RevocationWithRealCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		revoke func(t *testing.T, f *apiFixture) error
	}{
		{"rotate_secret", func(t *testing.T, f *apiFixture) error {
			_, err := RotateMachineSecret(t.Context(), f.vault, f.machineID,
				auditCtx{Actor: ActorAnonymous, Now: vaultNow})
			return err
		}},
		{"disable", func(t *testing.T, f *apiFixture) error {
			return DisableMachine(t.Context(), f.vault, f.machineID,
				auditCtx{Actor: ActorAnonymous, Now: vaultNow})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newAPIFixture(t)

			const authenticators = 24
			var (
				wg     sync.WaitGroup
				mu     sync.Mutex
				tokens []string
				start  = make(chan struct{})
			)
			for range authenticators {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					w := f.do(t, http.MethodPost, "/v1/auth/token", "",
						authTokenRequest{ClientID: f.clientID, ClientSecret: f.secret})
					if w.Code != http.StatusOK {
						return // 失効後の試行。正常。
					}
					var resp authTokenResponse
					if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
						t.Errorf("decode token: %v", err)
						return
					}
					mu.Lock()
					tokens = append(tokens, resp.Token)
					mu.Unlock()
				}()
			}

			revokeDone := make(chan struct{})
			go func() {
				defer close(revokeDone)
				<-start
				if err := tt.revoke(t, f); err != nil {
					t.Errorf("revoke: %v", err)
				}
			}()

			close(start)
			wg.Wait()
			<-revokeDone

			// **旧 credential 由来のトークンが 1 つも有効でないこと。**
			for _, token := range tokens {
				raw, err := DecodeToken(token)
				if err != nil {
					t.Fatalf("decode token: %v", err)
				}
				if _, ok := f.vault.LookupToken(raw, vaultNow); ok {
					t.Fatal("a token issued with the revoked credential is still valid")
				}
				// API 経由でも弾かれること。
				if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code == http.StatusOK {
					t.Fatal("a token issued with the revoked credential still reads secrets")
				}
			}
		})
	}
}

// rotate_secret の後、**旧 client_secret では認証できず、新しい方では通る**。
func TestRotateMachineSecretReplacesTheCredential(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	oldSecret := f.secret

	newSecret, err := RotateMachineSecret(t.Context(), f.vault, f.machineID,
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if err != nil {
		t.Fatalf("RotateMachineSecret: %v", err)
	}
	if newSecret == oldSecret {
		t.Fatal("the rotated secret is identical to the old one")
	}

	if w := f.do(t, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: f.clientID, ClientSecret: oldSecret}); w.Code != http.StatusUnauthorized {
		t.Errorf("auth with the old secret = %d, want 401", w.Code)
	}
	if w := f.do(t, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: f.clientID, ClientSecret: newSecret}); w.Code != http.StatusOK {
		t.Errorf("auth with the new secret = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
}

// **machine.disable / rotate_secret は監査失敗でも実行される**(fail open)。
// 緊急遮断操作を監査 DB の障害で止めてはならない(THREAT_MODEL §10.4)。
func TestRevocationIsFailOpen(t *testing.T) {
	t.Parallel()

	t.Run("disable", func(t *testing.T) {
		t.Parallel()

		f := newAPIFixture(t)
		token := f.token(t)
		breakAuditTable(t, f.store)

		if err := DisableMachine(t.Context(), f.vault, f.machineID,
			auditCtx{Actor: ActorAnonymous, Now: vaultNow}); err != nil {
			t.Fatalf("DisableMachine with a broken audit table: %v", err)
		}

		raw, err := DecodeToken(token)
		if err != nil {
			t.Fatalf("decode token: %v", err)
		}
		if _, ok := f.vault.LookupToken(raw, vaultNow); ok {
			t.Error("the token survived a disable that could not be audited")
		}
		active, err := MachineIsActive(t.Context(), f.store.DB(), f.machineID)
		if err != nil {
			t.Fatalf("MachineIsActive: %v", err)
		}
		if active {
			t.Error("the machine was not disabled")
		}
	})

	t.Run("rotate_secret", func(t *testing.T) {
		t.Parallel()

		f := newAPIFixture(t)
		token := f.token(t)
		breakAuditTable(t, f.store)

		newSecret, err := RotateMachineSecret(t.Context(), f.vault, f.machineID,
			auditCtx{Actor: ActorAnonymous, Now: vaultNow})
		if err != nil {
			t.Fatalf("RotateMachineSecret with a broken audit table: %v", err)
		}
		if newSecret == "" {
			t.Error("no new secret was returned")
		}

		raw, err := DecodeToken(token)
		if err != nil {
			t.Fatalf("decode token: %v", err)
		}
		if _, ok := f.vault.LookupToken(raw, vaultNow); ok {
			t.Error("the token survived a rotation that could not be audited")
		}
	})
}

// C9: **password_change と旧パスワードによるログインを並行実行し、変更後に
// 旧パスワード由来の有効セッションが存在しないことを確認する**(DESIGN §4.4)。
//
// argon2 の検証には数百 ms かかる。その間にパスワードが変更されると、
// 次の並びで旧パスワード由来のセッションが生き残る:
//
//	login:  旧 password_hash を読み、argon2 検証(数百 ms)
//	change: hash 更新 + 全 session DELETE + 監査を tx で commit
//	login:  新 session を INSERT           ← 削除をすり抜けた
//
// **競合ウィンドウが machine 側(C8)より現実的に広い**のは、argon2 の
// 所要時間がそのまま窓になるためである。
func TestC9PasswordChangeDoesNotRaceLogin(t *testing.T) {
	t.Parallel()

	const rounds = 2
	for round := range rounds {
		store := newTestStore(t)
		userID := newTestUser(t, store)

		const logins = 6
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			tokens   []string
			start    = make(chan struct{})
			nextPass = fmt.Sprintf("rotated-password-%d", round)
		)

		for range logins {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// **旧パスワードでログインを試みる。**
				res, err := Login(t.Context(), store.DB(), "admin", testPassword, "10.8.0.9", vaultNow)
				if err != nil {
					return // 変更が先に確定した。正常。
				}
				mu.Lock()
				tokens = append(tokens, res.Token)
				mu.Unlock()
			}()
		}

		changeDone := make(chan struct{})
		go func() {
			defer close(changeDone)
			<-start
			if _, err := ChangePassword(t.Context(), store.DB(), discardLogger(), userID,
				testPassword, nextPass, userAudit(userID, "10.8.0.9", vaultNow)); err != nil {
				t.Errorf("ChangePassword: %v", err)
			}
		}()

		close(start)
		wg.Wait()
		<-changeDone

		// **旧パスワード由来のセッションが 1 つも有効でないこと。**
		for _, token := range tokens {
			raw, err := DecodeSessionToken(token)
			if err != nil {
				t.Fatalf("decode session token: %v", err)
			}
			if _, err := LookupSession(t.Context(), store.DB(), raw, vaultNow); err == nil {
				t.Fatalf("round %d: a session created with the old password is still valid", round)
			}
		}

		// 変更そのものは成功している(競合で巻き戻っていない)。
		if _, err := Login(t.Context(), store.DB(), "admin", nextPass, "10.8.0.9", vaultNow); err != nil {
			t.Fatalf("round %d: the new password does not work: %v", round, err)
		}
	}
}

// C9 の隣接ケース: **同じユーザーへの password_change を 2 つ並行実行する。**
//
// 変更側は `UPDATE ... WHERE id = ? AND password_hash = ?`(検証に使ったハッシュ)
// + requireOneRow で決着する。この条件を落とすと、後から commit した方が
// 先の変更を黙って上書きし、**利用者が知らないパスワードが有効になる**
// (そして先勝ち側は「変更した」と思っている)。
func TestConcurrentPasswordChangesAllowOnlyOneWinner(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	userID := newTestUser(t, store)

	next := [2]string{"rotated-password-alpha", "rotated-password-bravo"}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		start  = make(chan struct{})
		winner = -1
		tokens = map[int]string{}
	)

	for i := range next {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			token, err := ChangePassword(t.Context(), store.DB(), discardLogger(), userID,
				testPassword, next[i], userAudit(userID, "10.8.0.9", vaultNow))
			if err != nil {
				return // 先に確定した方に負けた。正常。
			}
			mu.Lock()
			defer mu.Unlock()
			if winner >= 0 {
				t.Errorf("both password changes succeeded (%q and %q)", next[winner], next[i])
			}
			winner = i
			tokens[i] = token
		}()
	}
	close(start)
	wg.Wait()

	if winner < 0 {
		t.Fatal("neither password change succeeded")
	}

	// **勝った方のパスワードだけが有効。** 負けた方は保存されていない。
	var stored string
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&stored); err != nil {
		t.Fatalf("select password hash: %v", err)
	}
	ok, err := VerifyPassword(t.Context(), stored, next[winner])
	if err != nil || !ok {
		t.Fatalf("the winning password does not verify (ok=%v err=%v)", ok, err)
	}
	// 勝者のセッションは有効(自分を締め出さない)。
	raw, err := DecodeSessionToken(tokens[winner])
	if err != nil {
		t.Fatalf("DecodeSessionToken: %v", err)
	}
	if _, err := LookupSession(t.Context(), store.DB(), raw, vaultNow); err != nil {
		t.Errorf("the winner's new session is not valid: %v", err)
	}
}

// **password_change と user.disable を並行実行しても、無効化されたユーザーで
// 使えるセッションは残らない。**
//
// 変更側の argon2(数百 ms)は C9 と同じ競合ウィンドウであり、その間に
// 無効化が確定しうる。ここで見るのは「どちらが勝つか」ではなく、
// **緊急遮断(disable)の結果が競合で覆らないこと**である。
func TestPasswordChangeDoesNotRaceUserDisable(t *testing.T) {
	t.Parallel()

	const rounds = 2
	for round := range rounds {
		store := newTestStore(t)
		userID := newTestUser(t, store)
		existing := newTestSession(t, store, userID)

		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			token string
		)

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			// エラーはどちらでもよい(無効化が先なら失敗する)。
			token, _ = ChangePassword(t.Context(), store.DB(), discardLogger(), userID,
				testPassword, fmt.Sprintf("rotated-password-%d", round),
				userAudit(userID, "10.8.0.9", vaultNow))
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := DisableUser(t.Context(), store.DB(), discardLogger(), userID,
				auditCtx{Actor: ActorAnonymous, Now: vaultNow}); err != nil {
				t.Errorf("DisableUser: %v", err)
			}
		}()
		close(start)
		wg.Wait()

		// 無効化は覆らない。
		var disabled int
		if err := store.DB().QueryRowContext(t.Context(),
			`SELECT disabled FROM users WHERE id = ?`, userID).Scan(&disabled); err != nil {
			t.Fatalf("select user: %v", err)
		}
		if disabled != 1 {
			t.Fatalf("round %d: the user is no longer disabled", round)
		}

		// 既存セッションも、変更側が作ったセッションも使えない。
		if _, err := LookupSession(t.Context(), store.DB(), existing, vaultNow); err == nil {
			t.Errorf("round %d: an existing session survived the disable", round)
		}
		if token != "" {
			raw, err := DecodeSessionToken(token)
			if err != nil {
				t.Fatalf("DecodeSessionToken: %v", err)
			}
			if _, err := LookupSession(t.Context(), store.DB(), raw, vaultNow); err == nil {
				t.Errorf("round %d: a session created during the disable is usable", round)
			}
		}
		// ログインもできない(どちらのパスワードでも)。
		for _, pw := range []string{testPassword, fmt.Sprintf("rotated-password-%d", round)} {
			if _, err := Login(t.Context(), store.DB(), testUsername, pw, "10.8.0.9", vaultNow); err == nil {
				t.Errorf("round %d: a disabled user could log in", round)
			}
		}
	}
}
