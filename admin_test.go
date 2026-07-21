package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestAdmin は keyring 済みの DB に対する adminServer と MK を返す。
func newTestAdmin(t *testing.T) (*adminServer, *Vault, *Store, []byte) {
	t.Helper()

	v, store, mk := newTestVault(t)
	return newTestAdminFor(t, v), v, store, mk
}

// newTestAdminSealed は keyring を作らずに adminServer を返す。
// unseal を伴わないテスト(mux の疎通、timeout、seal の連打)で使い、
// keyring 作成ぶんの argon2 を省く。
func newTestAdminSealed(t *testing.T) *adminServer {
	t.Helper()

	return newTestAdminFor(t, newSealedVault(t))
}

func newTestAdminFor(t *testing.T, v *Vault) *adminServer {
	t.Helper()

	a := newAdminServer(v, discardLogger(), newRateLimiter(unsealRate, 1))
	a.now = func() time.Time { return vaultNow }
	return a
}

// doAdmin は adminMux に 1 リクエストを投げる。
func doAdmin(t *testing.T, a *adminServer, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	var r *http.Request
	if body == nil {
		r = httptest.NewRequestWithContext(t.Context(), method, path, nil)
	} else {
		r = httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	}
	w := httptest.NewRecorder()
	a.adminMux().ServeHTTP(w, r)
	return w
}

func decodeAdminStatus(t *testing.T, w *httptest.ResponseRecorder) adminStatusResponse {
	t.Helper()

	var s adminStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatalf("decode status response: %v (body %q)", err, w.Body.String())
	}
	return s
}

func TestAdminUnsealSealStatus(t *testing.T) {
	t.Parallel()

	a, v, store, mk := newTestAdmin(t)
	encoded := []byte(EncodeMasterKey(mk) + "\n") // op read / 手入力の末尾改行を模す

	if w := doAdmin(t, a, http.MethodGet, "/status", nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	} else if got := decodeAdminStatus(t, w); got.State != "sealed" {
		t.Fatalf("state = %q, want sealed", got.State)
	}

	w := doAdmin(t, a, http.MethodPost, "/unseal", encoded)
	if w.Code != http.StatusOK {
		t.Fatalf("unseal = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	if got := decodeAdminStatus(t, w); got.State != "unsealed" || got.DEKVersion != InitialDEKVersion {
		t.Fatalf("status after unseal = %+v", got)
	}
	if v.Status().State != StateUnsealed {
		t.Fatal("the vault was not unsealed")
	}

	if w := doAdmin(t, a, http.MethodPost, "/seal", nil); w.Code != http.StatusOK {
		t.Fatalf("seal = %d, want 200", w.Code)
	} else if got := decodeAdminStatus(t, w); got.State != "sealed" {
		t.Fatalf("state after seal = %q", got.State)
	}
	if v.Status().State != StateSealed {
		t.Fatal("the vault was not sealed")
	}

	// 監査ログが残っていること。
	if n := countAuditLogs(t, store.DB(), ActionUnsealAttempt); n != 1 {
		t.Errorf("%d unseal audit rows, want 1", n)
	}
	if n := countAuditLogs(t, store.DB(), ActionSeal); n != 1 {
		t.Errorf("%d seal audit rows, want 1", n)
	}
}

// レスポンスに鍵素材が混ざらないこと。
func TestAdminResponsesDoNotLeakKeyMaterial(t *testing.T) {
	t.Parallel()

	a, _, _, mk := newTestAdmin(t)
	encoded := EncodeMasterKey(mk)

	for _, w := range []*httptest.ResponseRecorder{
		doAdmin(t, a, http.MethodPost, "/unseal", []byte(encoded)),
		doAdmin(t, a, http.MethodGet, "/status", nil),
	} {
		body := w.Body.String()
		if strings.Contains(body, encoded) {
			t.Errorf("the response contains the master key: %q", body)
		}
		if bytes.Contains(w.Body.Bytes(), mk) {
			t.Errorf("the response contains raw key bytes: %q", body)
		}
	}
}

func TestAdminUnsealErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body func(mk []byte) []byte
		want int
	}{
		{"wrong master key", func(mk []byte) []byte {
			return []byte(EncodeMasterKey(flipByte(mk, 0)))
		}, http.StatusUnauthorized},
		{"malformed master key", func([]byte) []byte {
			return []byte("not base64!")
		}, http.StatusBadRequest},
		{"empty body", func([]byte) []byte { return []byte{} }, http.StatusBadRequest},
		{"master key with an embedded newline", func(mk []byte) []byte {
			encoded := EncodeMasterKey(mk)
			return []byte(encoded[:10] + "\n" + encoded[10:])
		}, http.StatusBadRequest},
		{"oversized body", func(mk []byte) []byte {
			return append([]byte(EncodeMasterKey(mk)), bytes.Repeat([]byte("A"), maxUnsealBody)...)
		}, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, v, _, mk := newTestAdmin(t)
			if w := doAdmin(t, a, http.MethodPost, "/unseal", tt.body(mk)); w.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %q)", w.Code, tt.want, w.Body.String())
			}
			if v.Status().State != StateSealed {
				t.Error("the vault was unsealed by an invalid request")
			}
		})
	}
}

func TestAdminUnsealTwiceIsConflict(t *testing.T) {
	t.Parallel()

	a, _, _, mk := newTestAdmin(t)
	encoded := []byte(EncodeMasterKey(mk))

	if w := doAdmin(t, a, http.MethodPost, "/unseal", encoded); w.Code != http.StatusOK {
		t.Fatalf("first unseal = %d", w.Code)
	}
	if w := doAdmin(t, a, http.MethodPost, "/unseal", encoded); w.Code != http.StatusConflict {
		t.Fatalf("second unseal = %d, want 409", w.Code)
	}
}

// unseal はグローバルに 3 回/分。argon2 を伴うので連打させない(DESIGN §7.4)。
func TestAdminUnsealIsRateLimited(t *testing.T) {
	t.Parallel()

	a, _, _, mk := newTestAdmin(t)
	// 誤った MK を使う。成功させると 2 回目以降が 409 になり、制限の確認に
	// ならない(失敗を繰り返せる状況こそが、制限が要る状況である)。
	wrong := []byte(EncodeMasterKey(flipByte(mk, 0)))

	for i := range unsealRate {
		if w := doAdmin(t, a, http.MethodPost, "/unseal", wrong); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	if w := doAdmin(t, a, http.MethodPost, "/unseal", wrong); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", unsealRate+1, w.Code)
	}

	// 正しい MK でも制限は同じ(キーを分けていない = グローバル)。
	if w := doAdmin(t, a, http.MethodPost, "/unseal", []byte(EncodeMasterKey(mk))); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a valid key bypassed the rate limit: %d", w.Code)
	}

	// ウィンドウが切り替われば通る。
	a.now = func() time.Time { return vaultNow.Add(rateWindow) }
	if w := doAdmin(t, a, http.MethodPost, "/unseal", []byte(EncodeMasterKey(mk))); w.Code != http.StatusOK {
		t.Fatalf("unseal after the window = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
}

// seal はレート制限されない。緊急遮断操作を止めてはならない。
func TestAdminSealIsNotRateLimited(t *testing.T) {
	t.Parallel()

	a := newTestAdminSealed(t)
	for i := range unsealRate * 3 {
		if w := doAdmin(t, a, http.MethodPost, "/seal", nil); w.Code != http.StatusOK {
			t.Fatalf("seal %d = %d, want 200", i+1, w.Code)
		}
	}
}

func TestAdminRotateMaster(t *testing.T) {
	t.Parallel()

	a, _, store, oldMK := newTestAdmin(t)
	newMK, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	body := []byte(EncodeMasterKey(oldMK) + "\n" + EncodeMasterKey(newMK) + "\n")
	if w := doAdmin(t, a, http.MethodPost, "/rotate-master", body); w.Code != http.StatusOK {
		t.Fatalf("rotate-master = %d, want 200 (body %q)", w.Code, w.Body.String())
	}

	kr, err := LoadKeyring(t.Context(), store.DB())
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	dek, err := kr.UnwrapDEK(newMK)
	if err != nil {
		t.Fatalf("the new master key does not open the keyring: %v", err)
	}
	Zero(dek)
}

func TestAdminRotateMasterBadRequests(t *testing.T) {
	t.Parallel()

	other, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tests := []struct {
		name string
		body func(mk []byte) []byte
		want int
		// reachesVault は「ボディの解釈を通り、RotateMaster まで到達するか」。
		// 到達しないケースで keyring を読み直しても、何も危険に晒されて
		// いないものを再確認するだけで、argon2 を 1 回余計に払う。
		reachesVault bool
	}{
		{name: "one line", want: http.StatusBadRequest, body: func(mk []byte) []byte {
			return []byte(EncodeMasterKey(mk) + "\n")
		}},
		{name: "three lines", want: http.StatusBadRequest, body: func(mk []byte) []byte {
			return []byte(EncodeMasterKey(mk) + "\n" + EncodeMasterKey(other) + "\n" + EncodeMasterKey(other) + "\n")
		}},
		{name: "malformed new key", want: http.StatusBadRequest, body: func(mk []byte) []byte {
			return []byte(EncodeMasterKey(mk) + "\nnope\n")
		}},
		{name: "identical keys", want: http.StatusBadRequest, body: func(mk []byte) []byte {
			return []byte(EncodeMasterKey(mk) + "\n" + EncodeMasterKey(mk) + "\n")
		}},
		{name: "wrong current key", want: http.StatusUnauthorized, reachesVault: true, body: func(mk []byte) []byte {
			return []byte(EncodeMasterKey(flipByte(mk, 0)) + "\n" + EncodeMasterKey(other) + "\n")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, _, store, mk := newTestAdmin(t)
			if w := doAdmin(t, a, http.MethodPost, "/rotate-master", tt.body(mk)); w.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %q)", w.Code, tt.want, w.Body.String())
			}
			if !tt.reachesVault {
				return
			}
			// **旧 MK が引き続き有効であること。**
			kr, err := LoadKeyring(t.Context(), store.DB())
			if err != nil {
				t.Fatalf("LoadKeyring: %v", err)
			}
			dek, err := kr.UnwrapDEK(mk)
			if err != nil {
				t.Fatalf("the current master key stopped working after a rejected rotate: %v", err)
			}
			Zero(dek)
		})
	}
}

// ボディ上限はエンドポイントごとに別である(DESIGN §7.4)。
//
// **同じ上限を使い回すと、どちらかが緩む。** unseal は 1 KB、rotate-master は
// 2 行ぶんで 2 KB。1 KB を超え 2 KB 未満のボディが、unseal では読み取り拒否に、
// rotate-master では読めた上で形式エラーになることで、別々に効いていると言える。
func TestAdminBodyLimitsArePerEndpoint(t *testing.T) {
	t.Parallel()

	a := newTestAdminSealed(t)
	between := bytes.Repeat([]byte("A"), maxUnsealBody+64) // 1 KB 超、2 KB 未満

	w := doAdmin(t, a, http.MethodPost, "/unseal", between)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unseal with a %d byte body = %d, want 400", len(between), w.Code)
	}
	if !strings.Contains(w.Body.String(), "read the request body") {
		t.Errorf("unseal error = %q, want the body to be rejected by the size limit", w.Body.String())
	}

	w = doAdmin(t, a, http.MethodPost, "/rotate-master", between)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("rotate-master with a %d byte body = %d, want 400", len(between), w.Code)
	}
	// 読めた上で「2 行ではない」と判断されている = 上限で切られていない。
	if !strings.Contains(w.Body.String(), "2 lines") {
		t.Errorf("rotate-master error = %q, want a parse error rather than a size error", w.Body.String())
	}
}

// 2 KB を超える rotate-master のボディは、切り詰めずに 400 で落ちる。
// 黙って切り詰めると、壊れた MK で rotate を試みる分かりにくい失敗になる。
func TestAdminRotateMasterOversizedBody(t *testing.T) {
	t.Parallel()

	a := newTestAdminSealed(t)
	body := bytes.Repeat([]byte("A"), maxRotateBody+1)

	w := doAdmin(t, a, http.MethodPost, "/rotate-master", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "read the request body") {
		t.Errorf("error = %q, want the oversized body to be rejected", w.Body.String())
	}
}

// I: parseRotateBody は各行に §6.1 の正規化(行末 CR の除去)を適用する。
//
// rotate-master のボディは改行区切り 2 行だが、Windows 由来の貼り付けで
// 行区切りが CRLF になることがある。"\n" で split すると、行末に "\r" が
// 残った状態で DecodeMasterKey に渡ってしまい、DecodeMasterKey は行中の
// CR/LF を一切許さない(折り返し MK 対策)ため、正しい MK でも誤解を招く
// 「invalid master key」になっていた。
func TestParseRotateBodyCRLF(t *testing.T) {
	t.Parallel()

	mk1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mk2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	body := []byte(EncodeMasterKey(mk1) + "\r\n" + EncodeMasterKey(mk2) + "\r\n")
	oldMK, newMK, err := parseRotateBody(body)
	if err != nil {
		t.Fatalf("parseRotateBody with CRLF line endings: %v", err)
	}
	if !bytes.Equal(oldMK, mk1) {
		t.Errorf("oldMK = %x, want %x", oldMK, mk1)
	}
	if !bytes.Equal(newMK, mk2) {
		t.Errorf("newMK = %x, want %x", newMK, mk2)
	}
}

// **行末以外(鍵の途中)に紛れ込んだ CR は、引き続き拒否される。** trailing
// CR の除去は「行区切りが CRLF だった」ケースだけを救うものであり、鍵の
// 内容そのものへの寛容さを増やすものではない。
func TestParseRotateBodyRejectsInteriorCR(t *testing.T) {
	t.Parallel()

	mk1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mk2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	encoded := EncodeMasterKey(mk1)
	withInteriorCR := encoded[:10] + "\r" + encoded[10:]
	body := []byte(withInteriorCR + "\n" + EncodeMasterKey(mk2) + "\n")

	if _, _, err := parseRotateBody(body); err == nil {
		t.Fatal("parseRotateBody accepted a key with an interior CR")
	}
}

// **seal は fail open。** 監査 DB が壊れていても、口の側で止めてはならない
// (THREAT_MODEL §10.4)。Vault 単体ではなく HTTP ハンドラでも確かめる。
func TestAdminSealSucceedsWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	v := NewVault(store.DB(), discardLogger(), 16)
	// unsealed 状態を argon2 なしで作る(この検証に必要なのは「消す対象の
	// DEK があること」だけで、鍵の導出そのものは vault_test.go で見ている)。
	v.state = StateUnsealed
	v.dek = bytes.Repeat([]byte{0xAB}, MasterKeyBytes)
	v.dekVersion = InitialDEKVersion
	dekAlias := v.dek

	a := newTestAdminFor(t, v)
	breakAuditTable(t, store)

	w := doAdmin(t, a, http.MethodPost, "/seal", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("seal = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	if got := decodeAdminStatus(t, w); got.State != "sealed" {
		t.Errorf("state = %q, want sealed", got.State)
	}
	if !bytes.Equal(dekAlias, make([]byte, MasterKeyBytes)) {
		t.Error("the dek was not zeroed when the audit log was unavailable")
	}
}

// **unseal は fail closed。** 監査を書けないなら unsealed にしない。
// 500 を返し、状態は sealed のままである。
func TestAdminUnsealFailsClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	a, v, store, mk := newTestAdmin(t)
	breakAuditTable(t, store)

	w := doAdmin(t, a, http.MethodPost, "/unseal", []byte(EncodeMasterKey(mk)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %q)", w.Code, w.Body.String())
	}
	if v.Status().State != StateSealed {
		t.Fatal("the vault was unsealed without an audit record")
	}
	// 失敗の詳細を口の側から返さない(監査 DB の状態を外へ漏らさない)。
	if strings.Contains(w.Body.String(), "audit") {
		t.Errorf("the response describes the internal failure: %q", w.Body.String())
	}
}

// 全てのレスポンスがキャッシュされないこと。admin の応答は状態そのもので
// あり、途中のプロキシや CLI に残ってよいものではない。
func TestAdminResponsesAreNotCacheable(t *testing.T) {
	t.Parallel()

	a := newTestAdminSealed(t)

	tests := []struct {
		name         string
		method, path string
		body         []byte
	}{
		{"status", http.MethodGet, "/status", nil},
		{"seal", http.MethodPost, "/seal", nil},
		{"unseal error", http.MethodPost, "/unseal", []byte("not base64!")},
		{"rotate-master error", http.MethodPost, "/rotate-master", []byte("one line\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := doAdmin(t, a, tt.method, tt.path, tt.body)
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := w.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
		})
	}
}

// adminMux は admin socket のパスだけを扱う。
//
// M4 / M5 で足す Machine API / Web UI のパスがここに現れないこと自体が、
// mux を共有していないことの確認になる(AGENTS.md ルール 29)。
func TestAdminMuxServesOnlyAdminPaths(t *testing.T) {
	t.Parallel()

	a := newTestAdminSealed(t)

	tests := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/status", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusNotFound},
		{http.MethodPost, "/v1/auth/token", http.StatusNotFound},
		{http.MethodGet, "/v1/secrets", http.StatusNotFound},
		{http.MethodGet, "/ui/login", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},

		// メソッドの取り違えも通さない。
		{http.MethodGet, "/unseal", http.StatusMethodNotAllowed},
		{http.MethodGet, "/seal", http.StatusMethodNotAllowed},
		{http.MethodPost, "/status", http.StatusMethodNotAllowed},
		{http.MethodGet, "/rotate-master", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			if w := doAdmin(t, a, tt.method, tt.path, nil); w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// ---- socket ----

func TestListenAdminSocketPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "run", "admin.sock")
	ln, err := listenAdminSocket(t.Context(), path)
	if err != nil {
		t.Fatalf("listenAdminSocket: %v", err)
	}
	defer func() { _ = ln.Close() }()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode().Type() != fs.ModeSocket {
		t.Errorf("mode = %v, want a socket", info.Mode())
	}
	// **0600 であること。** unseal / seal / rotate-master ができる口である。
	if perm := info.Mode().Perm(); perm != adminSocketMode {
		t.Errorf("permission = %04o, want %04o", perm, adminSocketMode)
	}
	// 親ディレクトリも他ユーザーに開けない。
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat socket directory: %v", err)
	}
	if perm := dir.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("directory permission = %04o, want no group/other access", perm)
	}
}

// 前回の異常終了で残ったソケットは張り直せる。
//
// 残骸を作るために、Close 時にファイルを消さない設定にしてから閉じる。
// **これが「listener は居ないがファイルは残っている」状態**であり、
// プロセスが SIGKILL された後に残るものと同じである。
func TestListenAdminSocketReplacesStaleSocket(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "admin.sock")
	first, err := listenAdminSocket(t.Context(), path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	unix, ok := first.(*net.UnixListener)
	if !ok {
		t.Fatalf("listener type = %T, want *net.UnixListener", first)
	}
	unix.SetUnlinkOnClose(false)
	if err := first.Close(); err != nil {
		t.Fatalf("close first listener: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket file is gone: %v", err)
	}

	second, err := listenAdminSocket(t.Context(), path)
	if err != nil {
		t.Fatalf("second listen: %v", err)
	}
	defer func() { _ = second.Close() }()
}

// **応答しているソケットは奪わない。**
//
// 消してから listen すると、既に動いている hokora を到達不能なまま(DB を
// 掴んだまま、場合によっては unsealed のまま)生かしてしまう。二重起動は
// 起動時に落とす。
func TestListenAdminSocketRefusesToStealALiveSocket(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "admin.sock")
	first, err := listenAdminSocket(t.Context(), path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	defer func() { _ = first.Close() }()

	// 接続を受け付ける状態にする(生きているプロセスを模す)。
	go func() {
		for {
			conn, err := first.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	second, err := listenAdminSocket(t.Context(), path)
	if err == nil {
		_ = second.Close()
		t.Fatal("listenAdminSocket stole a socket that another process was serving")
	}
	if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("error = %v, want it to say another process is listening", err)
	}
	// 元のソケットは生きたままであること。
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the original socket was removed: %v", err)
	}
}

// ソケット以外のファイルは消さない。パスの指定ミスでデータを消さないため。
func TestListenAdminSocketRefusesToRemoveNonSocket(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	if err := os.WriteFile(path, []byte("important"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := listenAdminSocket(t.Context(), path); err == nil {
		t.Fatal("listenAdminSocket removed a regular file")
	}
	// path は t.TempDir() 配下のテスト用ファイルである。
	if got, err := os.ReadFile(path); err != nil || string(got) != "important" { //nolint:gosec // G304
		t.Fatalf("the file was modified: %q, %v", got, err)
	}
}

// 親ディレクトリを作れないパスでは、listen する前に失敗する。
// 中途半端に listen したソケットを残さない。
func TestListenAdminSocketFailsWhenTheParentCannotBeCreated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	blocker := filepath.Join(dir, "run") // ディレクトリではなく通常ファイル
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	path := filepath.Join(blocker, "admin.sock")
	ln, err := listenAdminSocket(t.Context(), path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("listenAdminSocket succeeded under a non-directory parent")
	}
	if !strings.Contains(err.Error(), "admin socket directory") {
		t.Errorf("error = %v, want it to name the directory creation failure", err)
	}
	// 通常ファイルの下にソケットは作れない。blocker が壊されていないことで、
	// 途中まで作りかけて戻っていないことを確かめる。
	got, err := os.ReadFile(blocker) //nolint:gosec // G304: t.TempDir() 配下のテスト用ファイル
	if err != nil || string(got) != "not a directory" {
		t.Errorf("the blocking file was modified: %q, %v", got, err)
	}
}

// socket 越しに CLI クライアントの経路も含めて動くこと。
func TestAdminOverUnixSocket(t *testing.T) {
	t.Parallel()

	a, _, _, mk := newTestAdmin(t)
	path := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := listenAdminSocket(t.Context(), path)
	if err != nil {
		t.Fatalf("listenAdminSocket: %v", err)
	}

	srv := a.newAdminHTTPServer()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	status, err := adminCall(t.Context(), path, http.MethodGet, "/status", nil)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != "sealed" {
		t.Fatalf("state = %q, want sealed", status.State)
	}

	status, err = adminCall(t.Context(), path, http.MethodPost, "/unseal", []byte(EncodeMasterKey(mk)+"\n"))
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if status.State != "unsealed" {
		t.Fatalf("state = %q, want unsealed", status.State)
	}

	// エラーはメッセージとして返る(HTTP のステータスだけで潰れない)。
	if _, err := adminCall(t.Context(), path, http.MethodPost, "/unseal", []byte(EncodeMasterKey(mk))); err == nil {
		t.Fatal("a second unseal succeeded")
	} else if !strings.Contains(err.Error(), "already unsealed") {
		t.Errorf("error = %v, want it to mention that the vault is already unsealed", err)
	}

	if _, err := adminCall(t.Context(), path, http.MethodPost, "/seal", nil); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

// timeout がゼロだと無制限になる(DESIGN §7.4)。全て設定されていること。
func TestAdminHTTPServerTimeouts(t *testing.T) {
	t.Parallel()

	a := newTestAdminSealed(t)
	srv := a.newAdminHTTPServer()

	timeouts := map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	}
	for name, d := range timeouts {
		if d <= 0 {
			t.Errorf("%s = %v, want a positive duration", name, d)
		}
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Errorf("MaxHeaderBytes = %d, want a positive limit", srv.MaxHeaderBytes)
	}
}
