package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newServedDB は init 相当の DB を作り、そのパスを返す。
func newServedDB(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hokora.db")
	store := newTestStoreAt(t, path)
	if err := ensureKeyring(t.Context(), store, vaultNow); err != nil {
		t.Fatalf("ensureKeyring: %v", err)
	}
	return path
}

// **mlockall に失敗したら起動しない**(DESIGN §4.2)。
//
// swap に鍵が出る状態で「動いてはいる」のが最悪である。LimitMEMLOCK が
// 不足している環境をこれで検出する。
func TestRunServerAbortsWhenMlockallFails(t *testing.T) {
	t.Parallel()

	socket := filepath.Join(t.TempDir(), "admin.sock")
	wantErr := errors.New("mlockall failed (LimitMEMLOCK=infinity is required)")

	err := runServer(t.Context(), serveOptions{
		dbPath:      newServedDB(t),
		adminSocket: socket,
		lockMemory:  func() error { return wantErr },
		logger:      discardLogger(),
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want the mlockall failure", err)
	}
	// listener を作る前に落ちること(mlockall はどの初期化よりも先である)。
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Error("the admin socket was created even though mlockall failed")
	}
}

// serve は **sealed 状態で起動する**。起動しただけで secret は読めない。
func TestRunServerStartsSealedAndShutsDown(t *testing.T) {
	t.Parallel()

	socket := filepath.Join(t.TempDir(), "admin.sock")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runServer(ctx, serveOptions{
			dbPath:      newServedDB(t),
			adminSocket: socket,
			lockMemory:  func() error { return nil },
			ready:       func() { close(ready) },
			logger:      discardLogger(),
		})
	}()

	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("runServer returned before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("runServer did not become ready")
	}

	status, err := adminCall(t.Context(), socket, http.MethodGet, "/status", nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != "sealed" {
		t.Errorf("state = %q, want sealed at startup", status.State)
	}
	if status.Tokens != 0 {
		t.Errorf("tokens = %d, want 0 at startup", status.Tokens)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runServer: %v", err)
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("runServer did not shut down")
	}

	// shutdown 後は接続できない。
	if _, err := adminCall(t.Context(), socket, http.MethodGet, "/status", nil); err == nil {
		t.Error("the admin socket still answers after shutdown")
	}
}

// スキーマが無い DB では起動しない(OpenStore のバージョン検査)。
func TestRunServerRejectsUninitializedDatabase(t *testing.T) {
	t.Parallel()

	err := runServer(t.Context(), serveOptions{
		dbPath:      filepath.Join(t.TempDir(), "empty.db"),
		adminSocket: filepath.Join(t.TempDir(), "admin.sock"),
		lockMemory:  func() error { return nil },
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("runServer started against an uninitialized database")
	}
}

// **終了時は必ず seal する**(cmd_serve.go の shutdown)。プロセスが消えれば
// メモリも消えるが、明示的に消しておく方が core dump 等で残る窓が小さい。
//
// seal は fail open なので、監査 DB が壊れていても止まらない。
func TestShutdownSealsTheVault(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	v := NewVault(store.DB(), discardLogger(), 16)
	// unsealed 状態を argon2 なしで作る。ここで確かめたいのは「shutdown が
	// DEK を消すか」であって、鍵の導出そのものではない。
	v.state = StateUnsealed
	v.dek = bytes.Repeat([]byte{0xCD}, MasterKeyBytes)
	v.dekVersion = InitialDEKVersion
	dekAlias := v.dek

	breakAuditTable(t, store)

	if err := shutdown(&http.Server{ReadHeaderTimeout: time.Second}, v, discardLogger()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if got := v.Status(); got.State != StateSealed {
		t.Errorf("state = %v after shutdown, want sealed", got.State)
	}
	if !bytes.Equal(dekAlias, make([]byte, MasterKeyBytes)) {
		t.Error("shutdown left the dek in memory")
	}
}

// トークンの掃除は定期的に走るが、**期限判定ではない**(DESIGN §7.1)。
// runServer が回す ticker は 1 分間隔でテストから待てないので、掃除の中身
// (Vault.SweepTokens)が期限切れだけを落とすことを直接確かめる。
func TestSweepTokensRemovesOnlyExpiredTokens(t *testing.T) {
	t.Parallel()

	v := NewVault(newTestStore(t).DB(), discardLogger(), 16)
	v.state = StateUnsealed // 発行できる状態を argon2 なしで作る

	shortLived, _, err := v.IssueToken(vaultNow, func() (int64, error) { return 1, nil })
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	longLived, _, err := v.IssueToken(vaultNow.Add(TokenTTL), func() (int64, error) { return 2, nil })
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// 1 本目だけが期限切れになる時刻で掃除する。
	now := vaultNow.Add(TokenTTL + time.Second)
	v.SweepTokens(now)

	if got := v.Status().Tokens; got != 1 {
		t.Errorf("%d tokens after sweep, want 1", got)
	}
	if _, ok := v.LookupToken(decodeToken(t, shortLived), now); ok {
		t.Error("an expired token survived the sweep")
	}
	if _, ok := v.LookupToken(decodeToken(t, longLived), now); !ok {
		t.Error("a live token was removed by the sweep")
	}
}

// ---- init / gen-key ----

// init は keyring を作り、MK を一度だけ表示する。
func TestEnsureKeyringIsIdempotent(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if err := ensureKeyring(t.Context(), store, vaultNow); err != nil {
		t.Fatalf("ensureKeyring: %v", err)
	}
	before, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}

	// 2 回目は何もしない。**上書きすると既存の DEK を失い、全ての secret が
	// 復号不能になる。**
	if err := ensureKeyring(t.Context(), store, vaultNow); err != nil {
		t.Fatalf("second ensureKeyring: %v", err)
	}
	after, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}

	if string(after.DEKWrapped) != string(before.DEKWrapped) {
		t.Error("the keyring was replaced by a second init")
	}
	if string(after.KDFSalt) != string(before.KDFSalt) {
		t.Error("the kdf salt was replaced by a second init")
	}
}

// keyring を読めない DB では init を続行しない。
//
// **「読めない = まだ無い」と解釈すると、既存の keyring を上書きしかねない。**
// 上書きは既存 DEK の喪失であり、全ての secret が復号不能になる。
func TestEnsureKeyringPropagatesReadErrors(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if _, err := store.DB().ExecContext(t.Context(), `DROP TABLE keyring`); err != nil {
		t.Fatalf("drop keyring: %v", err)
	}

	err := ensureKeyring(t.Context(), store, vaultNow)
	if err == nil {
		t.Fatal("ensureKeyring succeeded even though the keyring could not be read")
	}
	// 「行が無い」と「読めない」を取り違えていないこと。
	if errors.Is(err, ErrKeyringMissing) {
		t.Errorf("error = %v, want a read failure rather than ErrKeyringMissing", err)
	}
}

// ---- stdin(MK の唯一の入力経路) ----

// readStdinLimited は上限を超えたら **切り詰めずにエラーにする**。
// 黙って切り詰めると、壊れた MK で unseal を試みる分かりにくい失敗になる。
//
// os.Stdin を差し替えるので t.Parallel() を呼ばない(main_test.go の
// captureOutput と同じ理由)。
func TestReadStdinLimited(t *testing.T) {
	const limit = 32

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "master key sized input", input: "abcdefgh", want: "abcdefgh"},
		{name: "trailing newline is preserved for DecodeMasterKey", input: "abc\n", want: "abc\n"},
		{name: "exactly at the limit", input: strings.Repeat("A", limit), want: strings.Repeat("A", limit)},
		{name: "one byte over the limit", input: strings.Repeat("A", limit+1), wantErr: "exceeds"},
		{name: "empty", input: "", wantErr: "stdin is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := os.Stdin
			t.Cleanup(func() { os.Stdin = orig })

			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("create pipe: %v", err)
			}
			if _, err := w.WriteString(tt.input); err != nil {
				t.Fatalf("write to pipe: %v", err)
			}
			w.Close()
			os.Stdin = r

			got, err := readStdinLimited(limit)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("readStdinLimited = %q, want an error", got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want it to mention %q", err, tt.wantErr)
				}
				// 秘密そのものをエラー文言に載せない(AGENTS.md ルール 20)。
				if tt.input != "" && strings.Contains(err.Error(), tt.input) {
					t.Errorf("error = %v, want it not to echo the input", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("readStdinLimited: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("readStdinLimited = %q, want %q", got, tt.want)
			}
		})
	}
}
