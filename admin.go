package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// admin socket のボディ上限(DESIGN §7.4)。
const (
	maxUnsealBody = 1 << 10 // 1 KB
	maxRotateBody = 2 << 10 // 2 KB
)

// adminSocketMode は admin socket のパーミッションである。
// unseal / seal / rotate-master ができる口なので、他ユーザーに開けない。
const adminSocketMode fs.FileMode = 0o600

// DefaultAdminSocket は admin socket の既定の位置である。
// systemd の RuntimeDirectory=hokora / RuntimeDirectoryMode=0700 と対応する。
const DefaultAdminSocket = "/run/hokora/admin.sock"

// adminServer は admin socket のハンドラである。
//
// **この口は Machine API / Web UI とは別の listener・別の ServeMux で動く**
// (AGENTS.md ルール 29)。2 つの http.Server を別のアドレスで起動しても、
// 同じ ServeMux を渡せば両方のアドレスで両方のパスが応答してしまうため、
// mux を共有しないことが境界そのものである。
type adminServer struct {
	vault  *Vault
	logger *slog.Logger

	// unsealLimiter は unseal をグローバルに 3 回/分へ制限する(DESIGN §7.4)。
	//
	// **socket と Web UI で同じインスタンスを共有する。** 設計表は経路ごと
	// ではなく「unseal(socket / Web) 3 回/分 グローバル」と書いており、
	// 別々に持つと片方を叩きながらもう片方も叩けてしまう。argon2 を伴う
	// 操作なので、連打で 64 MB × n の確保が積み上がらないようにする。
	unsealLimiter *rateLimiter

	now func() time.Time
}

func newAdminServer(v *Vault, logger *slog.Logger, unsealLimiter *rateLimiter) *adminServer {
	return &adminServer{
		vault:         v,
		logger:        logger,
		unsealLimiter: unsealLimiter,
		now:           time.Now,
	}
}

// adminMux は admin socket 専用の ServeMux を作る。**他の listener と共有しない。**
func (a *adminServer) adminMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /unseal", a.handleUnseal)
	mux.HandleFunc("POST /seal", a.handleSeal)
	mux.HandleFunc("GET /status", a.handleStatus)
	mux.HandleFunc("POST /rotate-master", a.handleRotateMaster)
	return mux
}

// adminWriteTimeout は admin socket の応答上限である。
//
// unseal / rotate-master は argon2 を伴い、semaphore の待ち行列にも入るため、
// 他の listener より長く取る。
const adminWriteTimeout = 60 * time.Second

// newAdminHTTPServer は admin socket 用の http.Server を作る。
//
// **timeout の設定は httpServerTimeouts に集約する**(DESIGN §7.4)。
// ここで struct literal を書き写すと、他の listener と値が食い違っても
// 誰も気付かない。
//
// ミドルウェア(no-store / パニックリカバリ)も他と同じものを被せる。
func (a *adminServer) newAdminHTTPServer() *http.Server {
	handler := withMiddleware("admin", a.adminMux(), a.logger)
	return httpServerTimeouts(handler, adminWriteTimeout, a.logger)
}

// ---- ハンドラ ----

func (a *adminServer) handleUnseal(w http.ResponseWriter, r *http.Request) {
	now := a.now()

	// レート制限はグローバル。攻撃者が変えられる値でキーを分けない。
	if !a.unsealLimiter.Allow(globalKey, now) {
		a.writeError(w, http.StatusTooManyRequests, "unseal is rate limited")
		return
	}

	body, ok := a.readBodyOrFail(w, r, maxUnsealBody)
	if !ok {
		return
	}
	defer Zero(body)

	mk, err := DecodeMasterKey(body)
	if err != nil {
		// 形式が不正な MK。値は返さない(AGENTS.md ルール 20)。
		a.writeError(w, http.StatusBadRequest, "invalid master key")
		return
	}
	defer Zero(mk)

	switch err := a.vault.Unseal(r.Context(), mk, socketAudit(now)); {
	case err == nil:
		a.writeStatus(w)
	case errors.Is(err, ErrAlreadyUnsealed):
		a.writeError(w, http.StatusConflict, "already unsealed")
	case errors.Is(err, ErrDecrypt):
		a.writeError(w, http.StatusUnauthorized, "invalid master key")
	case errors.Is(err, ErrKeyringMissing):
		a.writeError(w, http.StatusServiceUnavailable, ErrKeyringMissing.Error())
	default:
		a.logger.ErrorContext(r.Context(), "unseal failed", slog.String("error", err.Error()))
		a.writeError(w, http.StatusInternalServerError, "unseal failed")
	}
}

func (a *adminServer) handleSeal(w http.ResponseWriter, r *http.Request) {
	// seal は緊急遮断操作である。レート制限も、監査の成否も、これを止めない
	// (THREAT_MODEL §10.4)。
	a.vault.Seal(r.Context(), socketAudit(a.now()))
	a.writeStatus(w)
}

func (a *adminServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	a.writeStatus(w)
}

func (a *adminServer) handleRotateMaster(w http.ResponseWriter, r *http.Request) {
	body, ok := a.readBodyOrFail(w, r, maxRotateBody)
	if !ok {
		return
	}
	defer Zero(body)

	oldMK, newMK, err := parseRotateBody(body)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer Zero(oldMK)
	defer Zero(newMK)

	switch err := a.vault.RotateMaster(r.Context(), oldMK, newMK, socketAudit(a.now())); {
	case err == nil:
		a.writeStatus(w)
	case errors.Is(err, ErrDecrypt):
		// 現行 MK が誤り。旧 MK は引き続き有効なままである。
		a.writeError(w, http.StatusUnauthorized, "invalid current master key")
	case errors.Is(err, ErrKeyringMissing):
		a.writeError(w, http.StatusServiceUnavailable, ErrKeyringMissing.Error())
	default:
		a.logger.ErrorContext(r.Context(), "rotate-master failed", slog.String("error", err.Error()))
		a.writeError(w, http.StatusInternalServerError, "rotate-master failed")
	}
}

// parseRotateBody は rotate-master のボディを解釈する(DESIGN §6.7)。
//
// 形式は `<現行 MK>\n<新 MK>\n` の **改行区切り 2 行**。行数が 2 でなければ
// 400 にする。各行は §6.1 の正規化・検証を通す。
func parseRotateBody(body []byte) (oldMK, newMK []byte, err error) {
	lines := bytes.Split(trimSingleTrailingNewline(body), []byte("\n"))
	if len(lines) != 2 {
		return nil, nil, fmt.Errorf("expected 2 lines (current and new master key), got %d", len(lines))
	}
	// **各行に §6.1 の正規化を適用する**(DESIGN §6.7)。行区切りが CRLF の
	// 場合、"\n" split 後に前の行へ "\r" が残る。DecodeMasterKey は行中の
	// CR/LF を(折り返し MK 対策で)一切許さないため、行末の CR をここで
	// 落としておく(Windows 由来の貼り付けで誤解を招くエラーにしない)。
	for i := range lines {
		lines[i] = bytes.TrimSuffix(lines[i], []byte("\r"))
	}

	oldMK, err = DecodeMasterKey(lines[0])
	if err != nil {
		return nil, nil, errors.New("invalid current master key")
	}
	newMK, err = DecodeMasterKey(lines[1])
	if err != nil {
		Zero(oldMK)
		return nil, nil, errors.New("invalid new master key")
	}
	// 同じ MK への「ローテーション」は、運用上ほぼ確実に取り違えである。
	if constantTimeEqual(oldMK, newMK) {
		Zero(oldMK)
		Zero(newMK)
		return nil, nil, errors.New("the new master key is identical to the current one")
	}
	return oldMK, newMK, nil
}

// ---- レスポンス ----

// adminStatusResponse は /status および各操作の結果である。
// **鍵素材は含めない。**
type adminStatusResponse struct {
	State      string `json:"state"`
	DEKVersion int64  `json:"dek_version,omitempty"`
	Tokens     int    `json:"tokens"`
}

func (a *adminServer) writeStatus(w http.ResponseWriter) {
	s := a.vault.Status()
	a.writeJSON(w, http.StatusOK, adminStatusResponse{
		State:      s.State.String(),
		DEKVersion: s.DEKVersion,
		Tokens:     s.Tokens,
	})
}

type adminErrorResponse struct {
	Error string `json:"error"`
}

func (a *adminServer) writeError(w http.ResponseWriter, code int, msg string) {
	a.writeJSON(w, code, adminErrorResponse{Error: msg})
}

// writeJSON はレスポンスを書く。
//
// 書き込みの失敗はクライアントの切断であり、**状態は既に変わっている**
// (seal 済み / unseal 済み)。呼び出し側にできることは無いので、運用ログに
// 残すだけにする。握りつぶさないのは、socket が壊れていることに気付ける
// ようにするためである。
func (a *adminServer) writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	// ミドルウェアが付けるが、mux を直接叩く経路(テスト)でも効かせる。
	setNoStore(w)
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		a.logger.Warn("could not write the admin response",
			slog.Int("status", code), slog.String("error", err.Error()))
	}
}

// readBodyOrFail はボディを上限つきで読み、失敗したら 400 を書いて false を返す。
//
// **MaxBytesReader を全ての listener で使う**(AGENTS.md ルール 38)。
// 上限を超えた場合はエラーになる(黙って切り詰めない)。エラーの中身は返さない
// ── ボディは MK なので、読み取りエラーの文言に断片が乗る経路を作らない。
func (a *adminServer) readBodyOrFail(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	// r.Body は net/http が閉じる。ここで閉じない。
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "could not read the request body")
		return nil, false
	}
	return body, true
}

// ---- listener ----

// listenAdminSocket は admin socket を 0600 で開く。
//
// 既存のソケットファイルは、前回のプロセスが異常終了した残骸である場合に
// 限り取り除く。**ソケット以外のファイルは消さない**(パスの指定ミスで
// 別のファイルを消さないため)。
func listenAdminSocket(ctx context.Context, path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create admin socket directory: %w", err)
	}
	if err := removeStaleSocket(ctx, path); err != nil {
		return nil, err
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on admin socket: %w", err)
	}

	// listen から chmod までの間、ソケットは umask 依存のモードで存在する。
	// 親ディレクトリを 0700 で作ってあるため、この窓の間も他ユーザーからは
	// 到達できない。ディレクトリ側が緩められた場合に備えて、chmod の結果は
	// 下で読み直して確認する。
	if err := os.Chmod(path, adminSocketMode); err != nil {
		return nil, errors.Join(fmt.Errorf("chmod admin socket: %w", err), ln.Close())
	}
	// 「設定した」と「効いている」は違う。読み直して確認する。
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("stat admin socket: %w", err), ln.Close())
	}
	if perm := info.Mode().Perm(); perm != adminSocketMode {
		return nil, errors.Join(
			fmt.Errorf("admin socket permission is %04o, want %04o", perm, adminSocketMode),
			ln.Close(),
		)
	}
	return ln, nil
}

// removeStaleSocket は残骸のソケットを取り除く。
//
// **応答するソケットは奪わない。** 消してから listen すると、既に動いている
// hokora が居た場合に、そのプロセスを到達不能なまま(DB を掴んだまま、場合に
// よっては unsealed のまま)生かしてしまう。接続できるかどうかで生死を判定し、
// 生きていれば起動を中止する。
//
// 判定と listen の間には隙間があるが、これは同一ホストでの運用ミスを検出する
// ためのガードであって、権限境界ではない(境界はソケットの 0600 と親
// ディレクトリの 0700 である)。
func removeStaleSocket(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat admin socket path: %w", err)
	}
	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%s exists and is not a socket; refusing to remove it", path)
	}

	var d net.Dialer
	if conn, err := d.DialContext(ctx, "unix", path); err == nil {
		return errors.Join(
			fmt.Errorf("another process is already listening on %s", path),
			conn.Close(),
		)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale admin socket: %w", err)
	}
	return nil
}
