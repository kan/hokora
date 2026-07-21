package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
		machineAddr: "127.0.0.1:0",
		uiAddr:      "127.0.0.1:0",
		tlsDir:      newTestTLSDir(t),
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
	dbPath := newServedDB(t)
	tlsDir := newTestTLSDir(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runServer(ctx, serveOptions{
			dbPath:      dbPath,
			adminSocket: socket,
			machineAddr: "127.0.0.1:0",
			uiAddr:      "127.0.0.1:0",
			tlsDir:      tlsDir,
			lockMemory:  func() error { return nil },
			ready:       func(serverAddrs) { close(ready) },
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
		machineAddr: "127.0.0.1:0",
		uiAddr:      "127.0.0.1:0",
		tlsDir:      newTestTLSDir(t),
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

	servers := []*http.Server{{ReadHeaderTimeout: time.Second}}
	if err := shutdown(servers, v, discardLogger()); err != nil {
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

// SIGHUP が証明書リロードの契機として配線されていること(DESIGN §3.7)。
//
// **リロードそのものの挙動は server_test.go の certReloader のテストが見る。**
// ここで確かめるのは「シグナルが届くか」だけである。
func TestNotifySIGHUP(t *testing.T) {
	// シグナルはプロセス全体に届くので、並列にしない。
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ch := notifySIGHUP(ctx)

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP did not reach the reload channel")
	}

	// 連続して送っても詰まらない(取りこぼしてよい設計である)。
	for range 5 {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatalf("send SIGHUP: %v", err)
		}
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("a burst of SIGHUP did not reach the reload channel")
	}
}

// 証明書が無ければ起動しない。listener を張ってから気付くのでは遅い。
func TestRunServerRequiresACertificate(t *testing.T) {
	t.Parallel()

	err := runServer(t.Context(), serveOptions{
		dbPath:      newServedDB(t),
		adminSocket: filepath.Join(t.TempDir(), "admin.sock"),
		machineAddr: "127.0.0.1:0",
		uiAddr:      "127.0.0.1:0",
		tlsDir:      t.TempDir(), // 空
		lockMemory:  func() error { return nil },
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("runServer started without a tls key pair")
	}
}

// **配線そのものを、実際の 2 ポートへの接続で検証する。**
//
// server_test.go の TestMuxSeparation は mux を個別に組み直して検証しており、
// 「どの mux をどの listener に渡したか」は見ていない。startListeners の
// specs を取り違える(コピペで machineMux を両方に渡す)と、そこは素通りする。
// **これは AGENTS.md 冒頭の教訓そのものの再現経路である。**
func TestRunServerWiresEachMuxToItsOwnListener(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ready := make(chan serverAddrs, 1)
	done := make(chan error, 1)
	go func() {
		done <- runServer(ctx, serveOptions{
			dbPath:      newServedDB(t),
			adminSocket: filepath.Join(t.TempDir(), "admin.sock"),
			machineAddr: "127.0.0.1:0",
			uiAddr:      "127.0.0.1:0",
			tlsDir:      newTestTLSDir(t),
			lockMemory:  func() error { return nil },
			ready:       func(a serverAddrs) { ready <- a },
			logger:      discardLogger(),
		})
	}()

	var addrs serverAddrs
	select {
	case addrs = <-ready:
	case err := <-done:
		t.Fatalf("runServer returned before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("runServer did not become ready")
	}
	defer func() {
		cancel()
		<-done
	}()

	if addrs.Machine == addrs.UI {
		t.Fatalf("both listeners bound to %s", addrs.Machine)
	}

	// 自己署名証明書なので、テスト用に検証を通す CA として自分自身を積む。
	client := newTestTLSClient(t, addrs)

	tests := []struct {
		name string
		addr string
		path string
		want int
	}{
		// Machine API listener
		{"machine api serves healthz", addrs.Machine, "/healthz", http.StatusOK},
		{"machine api serves secrets", addrs.Machine, "/v1/secrets", http.StatusUnauthorized},
		{"machine api does not serve the ui", addrs.Machine, "/ui/login", http.StatusNotFound},
		{"machine api does not serve the admin socket", addrs.Machine, "/status", http.StatusNotFound},

		// **Web UI listener で /v1/* と /healthz が 404**(M4 完了条件)。
		{"web ui does not serve secrets", addrs.UI, "/v1/secrets", http.StatusNotFound},
		{"web ui does not serve healthz", addrs.UI, "/healthz", http.StatusNotFound},
		{"web ui does not serve the admin socket", addrs.UI, "/status", http.StatusNotFound},
		// Web UI は自分のルートを扱う(セッションが無いのでログインへ送られる)。
		{"web ui serves the login form", addrs.UI, "/ui/login", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"https://"+tt.addr+tt.path, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("get %s: %v", tt.path, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.want {
				t.Errorf("%s%s = %d, want %d", tt.addr, tt.path, resp.StatusCode, tt.want)
			}
			// **全レスポンスがキャッシュ不可であること。**
			// Web UI は DESIGN §8.3 の指定でより長い値を出すので、
			// 完全一致ではなく no-store を含むことを見る。
			if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
				t.Errorf("%s%s: Cache-Control = %q, want it to contain no-store", tt.addr, tt.path, got)
			}
		})
	}
}

// init は初期 admin を作り、パスワードを一度だけ表示する(Q3)。
//
// **`must_change_pw` を立てる。** 初回ログイン時に変更が求められ、その変更は
// sealed 状態でも動く(DESIGN §8.3)。
//
// **t.Parallel() を呼ばない。** captureOutput は os.Stdout / os.Stderr という
// パッケージ変数を差し替えるので、同時に走る他のテスト(cmdInit はマスター
// キーと初期パスワードを実際に印字する)の出力がこのパイプへ流れ込む。
// 並列化すると「別のテストが出した初期パスワード」を読んでログインを試み、
// 再現性なく落ちる。captureOutput の注意書きどおり順次実行する。
func TestEnsureInitialAdmin(t *testing.T) {
	store := newTestStore(t)

	var setupErr error
	_, stderr := captureOutput(t, func() {
		setupErr = ensureInitialAdmin(t.Context(), store, vaultNow)
	})
	if setupErr != nil {
		t.Fatalf("ensureInitialAdmin: %v", setupErr)
	}

	var (
		username   string
		mustChange int
		hash       string
	)
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT username, must_change_pw, password_hash FROM users`).
		Scan(&username, &mustChange, &hash); err != nil {
		t.Fatalf("select the initial admin: %v", err)
	}
	if username != initialAdminUsername {
		t.Errorf("username = %q, want %q", username, initialAdminUsername)
	}
	if mustChange != 1 {
		t.Error("must_change_pw was not set on the initial admin")
	}

	// 表示されたパスワードでログインできること(= 表示と保存が一致する)。
	password := extractInitialPassword(t, stderr)
	if _, err := Login(t.Context(), store.DB(), initialAdminUsername, password, "10.8.0.9", vaultNow); err != nil {
		t.Fatalf("login with the printed initial password: %v", err)
	}
	// **平文は保存されない。**
	if strings.Contains(hash, password) {
		t.Error("the initial password is stored in the database")
	}

	// 2 回目は何もしない(既存ユーザーを壊さない)。
	if err := ensureInitialAdmin(t.Context(), store, vaultNow); err != nil {
		t.Fatalf("second ensureInitialAdmin: %v", err)
	}
	var users int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 1 {
		t.Errorf("%d users, want 1", users)
	}
}

// extractInitialPassword は stderr の出力からパスワードを取り出す。
func extractInitialPassword(t *testing.T, out string) string {
	t.Helper()

	const marker = "initial password:"
	i := strings.Index(out, marker)
	if i < 0 {
		t.Fatalf("the initial password was not printed: %q", out)
	}
	line := strings.TrimSpace(strings.SplitN(out[i+len(marker):], "\n", 2)[0])
	if line == "" {
		t.Fatalf("the initial password line is empty: %q", out)
	}
	return line
}
