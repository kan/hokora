package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxAuthTokenBody は POST /v1/auth/token のボディ上限である(DESIGN §7.4)。
const maxAuthTokenBody = 4 << 10

// machineAPI は Machine API(:9443、machineMux)のハンドラである。
//
// **この mux は Web UI / admin socket とは共有しない**(AGENTS.md ルール 29)。
// listener を分けても同じ mux を渡せば、両方のポートで両方のパスが応答する。
type machineAPI struct {
	vault  *Vault
	db     *sql.DB
	logger *slog.Logger

	// 第一段は送信元 IP、第二段は client_id(DESIGN §7.4)。
	ipLimiter       *rateLimiter
	clientIDLimiter *rateLimiter

	now func() time.Time
}

func newMachineAPI(v *Vault, logger *slog.Logger) *machineAPI {
	return &machineAPI{
		vault:           v,
		db:              v.db,
		logger:          logger,
		ipLimiter:       newRateLimiter(authTokenRatePerIP, 0),
		clientIDLimiter: newRateLimiter(authTokenRatePerClientID, 0),
		now:             time.Now,
	}
}

// machineMux は Machine API 専用の ServeMux を作る。
func (a *machineAPI) machineMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/token", a.handleAuthToken)
	mux.HandleFunc("GET /v1/secrets", a.handleListSecrets)
	mux.HandleFunc("GET /v1/secrets/{key}", a.handleGetSecret)
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	return mux
}

// ---- POST /v1/auth/token ----

type authTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type authTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

func (a *machineAPI) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	now := a.now()
	remoteAddr := remoteIP(r)

	// 第一段: 送信元 IP。**攻撃者が変えられない値を先に置く**(ルール 35)。
	//
	// **ここでの拒否は監査しない。** 第一段はボディを読む前に効くので、
	// 記録すると「送信元 IP を変えながら大量に叩く」だけで監査 DB を
	// 膨らませられる。第二段(client_id)まで到達したものは記録する
	// ── そちらは既に 30 回/分の網を通過している。
	if !a.ipLimiter.Allow(remoteAddr, now) {
		a.writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	var req authTokenRequest
	if err := decodeJSONBody(w, r, maxAuthTokenBody, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	// 第二段: client_id。攻撃者制御の値なので、これ *だけ* には頼らない。
	if !a.clientIDLimiter.Allow(req.ClientID, now) {
		// 既に拒否は確定している。記録できなくても応答は 429 のままでよい
		// (「監査できないから認証を通す」ではなく、拒否側に倒れている)。
		if err := a.recordAuthFailure(r.Context(), req.ClientID, remoteAddr, now, ReasonRateLimited); err != nil {
			a.logger.ErrorContext(r.Context(), "could not record a rate limited auth attempt",
				slog.String("error", err.Error()))
		}
		a.writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	// **sealed なら検証を行わない**(DESIGN §8.1)。IssueToken は unsealed の
	// 確認・検証・store への追加を read lock 内で完結させる(C6)。
	token, expiresAt, err := a.vault.IssueToken(now, func() (int64, error) {
		return a.verifyForToken(r.Context(), req, remoteAddr, now)
	})
	switch {
	case err == nil:
		a.writeJSON(w, http.StatusOK, authTokenResponse{
			Token:     token,
			ExpiresIn: int(time.Until(expiresAt).Round(time.Second).Seconds()),
		})
	case errors.Is(err, ErrSealed):
		a.writeError(w, http.StatusServiceUnavailable, "sealed")
	case errors.Is(err, ErrInvalidCredentials):
		a.writeError(w, http.StatusUnauthorized, "invalid_credentials")
	default:
		// 監査が書けなかった場合もここに来る。**認証は通さない**(fail closed)。
		a.logger.ErrorContext(r.Context(), "token issuance failed", slog.String("error", err.Error()))
		a.writeError(w, http.StatusInternalServerError, "internal_error")
	}
}

// verifyForToken は credential を検証し、監査を確定させてから machine ID を返す。
//
// **Vault の read lock 内で呼ばれる**(C6)。ここから Vault のメソッドを
// 呼んではならない(自己デッドロックになる)。
//
// **監査は fail closed。** 成功・失敗とも、記録できなければ認証を拒否する
// (THREAT_MODEL §10.4。監査できないことを理由に認証を通してはならない)。
func (a *machineAPI) verifyForToken(ctx context.Context, req authTokenRequest, remoteAddr string, now time.Time) (int64, error) {
	machine, err := verifyMachineCredentials(ctx, a.db, req.ClientID, req.ClientSecret)
	if err != nil {
		// **応答はどちらも invalid_credentials に潰す**(区別を漏らさない)。
		// 監査 detail の理由だけを分ける: disabled(退役済み machine の設定ミス)
		// と invalid_credentials(総当たり等)を運用側で見分けられるように。
		var reason string
		switch {
		case errors.Is(err, errMachineDisabled):
			reason = ReasonDisabled
		case errors.Is(err, ErrInvalidCredentials):
			reason = ReasonInvalidCredentials
		default:
			return 0, err // DB 障害等。認証は通さない。
		}
		if auditErr := a.recordAuthFailure(ctx, req.ClientID, remoteAddr, now, reason); auditErr != nil {
			return 0, auditErr
		}
		return 0, ErrInvalidCredentials
	}

	// 成功の監査と last_auth_at の更新を 1 トランザクションにまとめる。
	if err := a.recordAuthSuccess(ctx, machine.ID, remoteAddr, now); err != nil {
		return 0, err
	}
	return machine.ID, nil
}

func (a *machineAPI) recordAuthSuccess(ctx context.Context, machineID int64, remoteAddr string, now time.Time) error {
	return withTx(ctx, a.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE machines SET last_auth_at = ? WHERE id = ?`, now.Unix(), machineID); err != nil {
			return fmt.Errorf("update last_auth_at: %w", err)
		}
		ac := machineAudit(machineID, remoteAddr, now)
		return RecordAudit(ctx, tx, ac.machineEntry(ActionAuthMachine, machineID))
	})
}

// recordAuthFailure は認証失敗を記録する。
//
// **actor は anonymous、client_id は subject_digest に潰す**(DESIGN §5.5)。
// 生の client_id を actor や target に入れると、そこが攻撃者制御の文字列の
// 入口になる。digest なら「同じ存在しない client_id が繰り返し試された」ことは
// 追える。
func (a *machineAPI) recordAuthFailure(ctx context.Context, clientID, remoteAddr string, now time.Time, reason string) error {
	digest := subjectDigest(clientID)
	ac := anonymousAudit(remoteAddr, now)
	return RecordAudit(ctx, a.db, ac.entry(ActionAuthMachine, ResultFailure, &AuditDetail{
		Reason:        &reason,
		SubjectDigest: &digest,
	}))
}

// ---- GET /v1/secrets ----

type listSecretsResponse struct {
	Project string            `json:"project"`
	Env     string            `json:"env"`
	Secrets map[string]string `json:"secrets"`
}

func (a *machineAPI) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	req, ok := a.authorize(w, r)
	if !ok {
		return
	}

	secrets, err := ListEncryptedSecrets(r.Context(), a.db, req.env.EnvironmentID)
	if err != nil {
		a.internalError(w, r, "list secrets", err)
		return
	}

	values, ok := a.decryptAndRecord(w, r, req, secrets)
	if !ok {
		return
	}

	a.writeJSON(w, http.StatusOK, listSecretsResponse{
		Project: req.env.ProjectSlug,
		Env:     req.env.EnvSlug,
		Secrets: values,
	})
}

// ---- GET /v1/secrets/{key} ----

type getSecretResponse struct {
	Project string `json:"project"`
	Env     string `json:"env"`
	Key     string `json:"key"`
	Value   string `json:"value"`
}

// handleGetSecret は 1 件の secret を返す。
//
// **常に最新バージョンである。version パラメータは存在しない**(DESIGN §8.1)。
func (a *machineAPI) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	req, ok := a.authorize(w, r)
	if !ok {
		return
	}

	key := r.PathValue("key")
	// key の形式検査を先に行う。**エラーに値を載せない**ため、結果は捨てる。
	// **失敗した read も監査する**(ルール 22)。認証済みの主体が拒否された
	// 事実は denySecretAccess で記録する(list エンドポイントと揃える)。
	if err := ValidateItemKey(key); err != nil {
		a.denySecretAccess(w, r, req.machineID, req.now)
		return
	}

	secret, err := GetEncryptedSecret(r.Context(), a.db, req.env.EnvironmentID, key)
	if errors.Is(err, ErrNotFound) {
		// 存在しない key と grant なしを区別しない(ルール 54 と同じ理由)。
		a.denySecretAccess(w, r, req.machineID, req.now)
		return
	}
	if err != nil {
		a.internalError(w, r, "get secret", err)
		return
	}

	values, ok := a.decryptAndRecord(w, r, req, []EncryptedSecret{*secret})
	if !ok {
		return
	}

	a.writeJSON(w, http.StatusOK, getSecretResponse{
		Project: req.env.ProjectSlug,
		Env:     req.env.EnvSlug,
		Key:     secret.Key,
		Value:   values[secret.Key],
	})
}

// ---- GET /healthz ----

// handleHealthz は認証不要の生存確認である。
//
// **バージョン文字列を返さない**(AGENTS.md ルール 33)。sealed / unsealed も
// 返さない。未認証で到達できる口から、攻撃の下調べに使える情報を出さない。
func (a *machineAPI) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	setNoStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok\n")); err != nil {
		a.logger.Warn("could not write the healthz response", slog.String("error", err.Error()))
	}
}

// ---- 共通処理 ----

// authorizedRequest は認証・認可を通ったリクエストである。
type authorizedRequest struct {
	machineID  int64
	remoteAddr string
	now        time.Time
	env        *EnvironmentRef
}

// authorize はトークンを検証し、認可を再検査する(DESIGN §4.5)。
//
// 失敗時はレスポンスを書いて false を返す。**理由は区別しない。**
func (a *machineAPI) authorize(w http.ResponseWriter, r *http.Request) (authorizedRequest, bool) {
	now := a.now()

	// **トークンが無い / 無効な場合は監査しない。**
	//
	// ここには actor が無く(誰の試行か分からない)、対象も特定できない。
	// 一方この経路はレート制限を持たないため(DESIGN §7.4 は
	// /v1/auth/token だけを制限する)、記録すると未認証のトラフィックだけで
	// 監査 DB を膨らませられる。**記録するのは「認証済みの主体が拒否された」
	// 場合に限る**(下記 denySecretAccess)。
	raw, err := bearerToken(r)
	if err != nil {
		a.writeError(w, http.StatusUnauthorized, "invalid_token")
		return authorizedRequest{}, false
	}
	defer Zero(raw)

	// 期限は Lookup が検査する(sweep に依存しない。DESIGN §7.1)。
	machineID, ok := a.vault.LookupToken(raw, now)
	if !ok {
		a.writeError(w, http.StatusUnauthorized, "invalid_token")
		return authorizedRequest{}, false
	}

	projectSlug := r.URL.Query().Get("project")
	envSlug := r.URL.Query().Get("env")
	if ValidateSlug(projectSlug) != nil || ValidateSlug(envSlug) != nil {
		// 形式が不正な slug は「見つからない」と同じに潰す。
		a.denySecretAccess(w, r, machineID, now)
		return authorizedRequest{}, false
	}

	env, err := authorizeEnvironment(r.Context(), a.db, machineID, projectSlug, envSlug)
	if errors.Is(err, ErrForbidden) {
		a.denySecretAccess(w, r, machineID, now)
		return authorizedRequest{}, false
	}
	if err != nil {
		a.internalError(w, r, "authorize", err)
		return authorizedRequest{}, false
	}

	return authorizedRequest{
		machineID:  machineID,
		remoteAddr: remoteIP(r),
		now:        now,
		env:        env,
	}, true
}

// denySecretAccess は認証済みリクエストの拒否を記録し、403 を返す。
//
// **失敗した読み取りも監査対象である**(AGENTS.md ルール 22)。誰が、いつ、
// どこから拒否されたかは、grant の設定ミスと探索行為の両方の手掛かりになる。
//
// **対象(target)は記録しない。** 拒否された時点で、要求された project /
// env が実在するかどうかは確定していない。リクエストの生の slug を入れれば
// 攻撃者制御の文字列が DB に入り(ルール 25)、解決済みの ID を入れれば
// 存在情報が監査ログ経由で漏れる。記録するのは actor と拒否の事実に留める。
//
// **記録できなければ 500 にする**(fail closed)。「記録されない secret への
// アクセス」を残さない。どのみち secret は返らない。
func (a *machineAPI) denySecretAccess(w http.ResponseWriter, r *http.Request, machineID int64, now time.Time) {
	reason := ReasonForbidden
	ac := machineAudit(machineID, remoteIP(r), now)
	entry := ac.entry(ActionSecretRead, ResultFailure, &AuditDetail{Reason: &reason})
	entry.TargetMachineID = &machineID

	if err := RecordAudit(r.Context(), a.db, entry); err != nil {
		a.internalError(w, r, "record a denied secret access", err)
		return
	}
	a.writeError(w, http.StatusForbidden, "forbidden")
}

// decryptAndRecord は復号してから監査を確定させる。**この順序を 1 箇所に
// 固定する**ため、ハンドラから直接 decryptAll / recordSecretReads を呼ばない。
//
// 監査が書けなければ secret を返さない(fail closed。THREAT_MODEL §10.4)。
// 逆順にすると「返せなかった読み取り」が success として残る。
func (a *machineAPI) decryptAndRecord(w http.ResponseWriter, r *http.Request, req authorizedRequest, secrets []EncryptedSecret) (map[string]string, bool) {
	values, err := a.decryptAll(secrets)
	if errors.Is(err, ErrSealed) {
		// authorize 通過後に seal が完了した競合窓。**500 ではなく 503** を返し、
		// SDK の ErrSealed マッピングに乗せる(通常は seal 時のトークン全削除で
		// 401 になるため、この窓は極小)。
		a.writeError(w, http.StatusServiceUnavailable, "sealed")
		return nil, false
	}
	if err != nil {
		a.internalError(w, r, "decrypt secrets", err)
		return nil, false
	}

	// **key ごとに 1 レコードを、1 トランザクションで N 行 INSERT する**
	// (AGENTS.md ルール 23)。commit が成功してからレスポンスを送る。
	if err := a.recordSecretReads(r.Context(), req, secrets); err != nil {
		a.internalError(w, r, "record secret reads", err)
		return nil, false
	}
	return values, true
}

// decryptAll は暗号文を復号する。**Vault の read lock 内で完結させる**(C1)。
//
// fn を抜けた後に DEK を参照しないよう、復号はこの中で終わらせる。
func (a *machineAPI) decryptAll(secrets []EncryptedSecret) (map[string]string, error) {
	values := make(map[string]string, len(secrets))
	err := a.vault.WithDEK(func(dek []byte, dekVersion int64) error {
		for _, s := range secrets {
			plaintext, err := decryptSecret(dek, dekVersion, s)
			if err != nil {
				return err
			}
			values[s.Key] = string(plaintext)
			Zero(plaintext)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}

// recordSecretReads は読み取りを key ごとに 1 行、1 トランザクションで記録する。
//
// **fail closed。** ここが失敗したら secret を返さない(THREAT_MODEL §10.4)。
// result = success は「認可を通過し、復号に成功し、レスポンスの送信を開始した」
// を意味する(§10.5)。
func (a *machineAPI) recordSecretReads(ctx context.Context, req authorizedRequest, secrets []EncryptedSecret) error {
	return withTx(ctx, a.db, func(tx *sql.Tx) error {
		ac := machineAudit(req.machineID, req.remoteAddr, req.now)
		for _, s := range secrets {
			// target は DB から読んだ値だけで組み立てる。リクエストの生の
			// 文字列は入れない(AGENTS.md ルール 25)。
			target := req.env.ProjectSlug + "/" + req.env.EnvSlug + "/" + s.Key
			version := int(s.Version)

			entry := ac.entry(ActionSecretRead, ResultSuccess, &AuditDetail{Version: &version})
			entry.Target = &target
			entry.TargetProjectID = &req.env.ProjectID
			entry.TargetEnvironmentID = &req.env.EnvironmentID
			entry.TargetItemID = &s.ItemID
			entry.TargetMachineID = &req.machineID
			if err := RecordAudit(ctx, tx, entry); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *machineAPI) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	// 詳細は運用ログにだけ出す。レスポンスには理由を載せない。
	a.logger.ErrorContext(r.Context(), what, slog.String("error", err.Error()))
	a.writeError(w, http.StatusInternalServerError, "internal_error")
}

// bearerToken は Authorization ヘッダからトークンを取り出す。
func bearerToken(r *http.Request) ([]byte, error) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, ErrInvalidToken
	}
	return DecodeToken(header[len(prefix):])
}

// remoteIP は送信元 IP を返す。
//
// **X-Forwarded-For を見ない。** Machine API はリバースプロキシを介さず
// firewalld で到達制限する構成であり(DESIGN §4.1)、ヘッダを信用すると
// レート制限のキーが攻撃者制御の値になる(AGENTS.md ルール 35)。
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// decodeJSONBody はボディを上限つきで読み、JSON として解釈する。
//
// **未知のフィールドを拒否する。** 綴り違いを黙って無視すると、意図しない
// 既定値で処理が進む。
func decodeJSONBody(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	return nil
}

// ---- レスポンス ----

type apiErrorResponse struct {
	Error string `json:"error"`
}

func (a *machineAPI) writeError(w http.ResponseWriter, code int, reason string) {
	a.writeJSON(w, code, apiErrorResponse{Error: reason})
}

func (a *machineAPI) writeJSON(w http.ResponseWriter, code int, body any) {
	writeAPIJSON(w, code, body, a.logger)
}

// writeAPIJSON はレスポンスを書く。
//
// **書き込み失敗はクライアントの切断である。** 監査は既に確定しており、
// 「送信を開始した」以上 success の記録は覆さない(THREAT_MODEL §10.5)。
// 呼び出し側にできることは無いが、握りつぶさずに運用ログへ出す
// (socket が壊れていることに気付けるようにする)。
func writeAPIJSON(w http.ResponseWriter, code int, body any, logger *slog.Logger) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.Warn("could not write the api response",
			slog.Int("status", code), slog.String("error", err.Error()))
	}
}

// setNoStore は全レスポンスに Cache-Control: no-store を付ける。
func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}
