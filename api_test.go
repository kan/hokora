package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// apiFixture は Machine API のテスト一式である。
//
// project(myapp)/ environment(prod)に secret を 2 件置き、その env への
// grant を持つ machine を 1 台用意する。
type apiFixture struct {
	api      *machineAPI
	vault    *Vault
	store    *Store
	mk       []byte
	clientID string
	secret   string

	machineID     int64
	projectID     int64
	environmentID int64
}

const (
	testProjectSlug = "myapp"
	testEnvSlug     = "prod"
)

// testSecretValue はテスト用のダミー値である。**実在の credential ではない。**
// 平文がレスポンスや監査ログに漏れていないことを検査するために、特徴的な
// 文字列にしてある。
var testSecretValue = "postgres://user:" + "pass@localhost/db"

// newAPIFixture は unsealed な Machine API を組み立てる(argon2 は 1 回)。
func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()

	v, store, mk := newTestVault(t)
	unsealForTest(t, v, mk)

	f := &apiFixture{
		api:      newMachineAPI(v, discardLogger()),
		vault:    v,
		store:    store,
		mk:       mk,
		clientID: "app-prod",
	}
	f.api.now = func() time.Time { return vaultNow }

	id, secret, err := CreateMachine(t.Context(), store.DB(), f.clientID, "app server",
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	f.machineID, f.secret = id, secret

	f.projectID = insertProject(t, store.DB(), testProjectSlug, false)
	f.environmentID = insertEnvironment(t, store.DB(), f.projectID, testEnvSlug, false)
	f.grant(t, f.environmentID)

	f.putSecret(t, "DATABASE_URL", testSecretValue)
	f.putSecret(t, "API_TOKEN", "t0ken")
	return f
}

// grant は machine に environment への grant を与える。
func (f *apiFixture) grant(t *testing.T, environmentID int64) {
	t.Helper()

	if _, err := f.store.DB().ExecContext(t.Context(),
		`INSERT INTO machine_grants (machine_id, environment_id, created_at) VALUES (?, ?, ?)`,
		f.machineID, environmentID, vaultNow.Unix()); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
}

// putSecret は item と暗号化済みの値を 1 件書く。
//
// 書き込み API は M5 の範囲なので、ここでは暗号レイヤーを直接使って行を作る。
func (f *apiFixture) putSecret(t *testing.T, key, value string) {
	t.Helper()

	if err := ValidateSecretValue([]byte(value)); err != nil {
		t.Fatalf("ValidateSecretValue: %v", err)
	}

	res, err := f.store.DB().ExecContext(t.Context(), `
		INSERT INTO items (environment_id, key, current_version, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?)`, f.environmentID, key, vaultNow.Unix(), vaultNow.Unix())
	if err != nil {
		t.Fatalf("insert item: %v", err)
	}
	itemID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("insert item: %v", err)
	}

	err = f.vault.WithDEK(func(dek []byte, dekVersion int64) error {
		aad, err := itemAAD(itemID, 1, dekVersion)
		if err != nil {
			return err
		}
		ciphertext, nonce, err := sealBytes(dek, []byte(value), aad)
		if err != nil {
			return err
		}
		_, err = f.store.DB().ExecContext(t.Context(), `
			INSERT INTO item_versions (item_id, version, value_enc, nonce, dek_version, created_at, created_by)
			VALUES (?, 1, ?, ?, ?, ?, 'test')`,
			itemID, ciphertext, nonce, dekVersion, vaultNow.Unix())
		return err
	})
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
}

// do は machineMux に 1 リクエストを送る。
func (f *apiFixture) do(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var r *http.Request
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		r = httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(encoded))
	} else {
		r = httptest.NewRequestWithContext(t.Context(), method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.RemoteAddr = "10.0.0.2:53124"

	w := httptest.NewRecorder()
	f.api.machineMux().ServeHTTP(w, r)
	return w
}

// token は認証してトークンを取る。
func (f *apiFixture) token(t *testing.T) string {
	t.Helper()

	w := f.do(t, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: f.clientID, ClientSecret: f.secret})
	if w.Code != http.StatusOK {
		t.Fatalf("auth token = %d, want 200 (body %q)", w.Code, w.Body.String())
	}

	var resp authTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp.Token
}

func secretsPath(project, env string) string {
	return fmt.Sprintf("/v1/secrets?project=%s&env=%s", project, env)
}

func decodeAPIError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	var e apiErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error response: %v (body %q)", err, w.Body.String())
	}
	return e.Error
}

// ---- 正常系 ----

func TestAPIAuthAndFetchSecrets(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list secrets = %d, want 200 (body %q)", w.Code, w.Body.String())
	}

	var resp listSecretsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Project != testProjectSlug || resp.Env != testEnvSlug {
		t.Errorf("project/env = %q/%q", resp.Project, resp.Env)
	}
	if got := resp.Secrets["DATABASE_URL"]; got != testSecretValue {
		t.Errorf("DATABASE_URL = %q", got)
	}
	if got := resp.Secrets["API_TOKEN"]; got != "t0ken" {
		t.Errorf("API_TOKEN = %q", got)
	}

	// **key ごとに 1 レコード**(AGENTS.md ルール 23)。
	if n := countAuditLogs(t, f.store.DB(), ActionSecretRead); n != 2 {
		t.Errorf("%d secret.read audit rows, want 2", n)
	}

	// 単体取得も同じ値を返す。
	w = f.do(t, http.MethodGet, "/v1/secrets/DATABASE_URL?project=myapp&env=prod", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get secret = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	var one getSecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if one.Value != testSecretValue || one.Key != "DATABASE_URL" {
		t.Errorf("get secret = %+v", one)
	}
}

// 全レスポンスに Cache-Control: no-store(DESIGN §8.1)。
func TestAPIResponsesAreNotCacheable(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	for _, path := range []string{
		"/healthz",
		secretsPath(testProjectSlug, testEnvSlug),
		"/v1/secrets/DATABASE_URL?project=myapp&env=prod",
	} {
		w := f.do(t, http.MethodGet, path, token, nil)
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
	}
}

// /healthz は認証不要だが、**バージョン文字列を返さない**(ルール 33)。
func TestAPIHealthz(t *testing.T) {
	t.Parallel()

	// /healthz は vault にも DB にも触らないので、fixture を組まない
	// (組むと argon2 を 2 回払う)。
	api := &machineAPI{logger: discardLogger(), now: func() time.Time { return vaultNow }}

	w := httptest.NewRecorder()
	api.machineMux().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, forbidden := range []string{"hokora", "version", "1.", "go1", "sealed", "unsealed"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("healthz body %q contains %q", body, forbidden)
		}
	}
}

// ---- 認証 ----

func TestAPIAuthFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		clientID   string
		secret     string
		wantStatus int
		wantError  string
	}{
		{"wrong secret", "app-prod", "not-the-secret", http.StatusUnauthorized, "invalid_credentials"},
		{"unknown client id", "does-not-exist", "whatever", http.StatusUnauthorized, "invalid_credentials"},
		{"empty credentials", "", "", http.StatusUnauthorized, "invalid_credentials"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newAPIFixture(t)
			w := f.do(t, http.MethodPost, "/v1/auth/token", "",
				authTokenRequest{ClientID: tt.clientID, ClientSecret: tt.secret})

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", w.Code, tt.wantStatus, w.Body.String())
			}
			// **client_id 不在と secret 不一致を区別しない**(DESIGN §8.1)。
			if got := decodeAPIError(t, w); got != tt.wantError {
				t.Errorf("error = %q, want %q", got, tt.wantError)
			}
		})
	}
}

// 存在しない client_id での失敗は、**actor = anonymous + subject_digest** で
// 記録される(DESIGN §5.5)。生の入力値が DB に入らないこと。
func TestAPIAuthFailureAuditDoesNotStoreRawClientID(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	const evil = "app-prod\n'; DROP TABLE audit_logs;--"

	w := f.do(t, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: evil, ClientSecret: "x"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}

	var actor, detail string
	var machineID sql.NullInt64
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT actor, actor_machine_id, detail FROM audit_logs
		WHERE action = ? AND result = ?`,
		string(ActionAuthMachine), string(ResultFailure),
	).Scan(&actor, &machineID, &detail); err != nil {
		t.Fatalf("select audit row: %v", err)
	}

	if actor != ActorAnonymous {
		t.Errorf("actor = %q, want %q", actor, ActorAnonymous)
	}
	if machineID.Valid {
		t.Errorf("actor_machine_id = %v, want NULL", machineID)
	}
	if strings.Contains(detail, "DROP TABLE") || strings.Contains(detail, "app-prod") {
		t.Errorf("detail contains the raw client id: %q", detail)
	}
	if !strings.Contains(detail, subjectDigest(evil)) {
		t.Errorf("detail = %q, want it to contain the subject digest", detail)
	}
}

// D: disabled な machine が **正しい** secret で認証しても、応答は
// wrong-secret と同じ invalid_credentials(401)である(区別を漏らさない)。
// **監査 detail だけは reason=disabled で残り**、運用側で「退役済み machine
// の設定ミス」と「総当たり」を区別できる。
func TestAPIAuthFailureForDisabledMachineIsIndistinguishableButAudited(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	if err := DisableMachine(t.Context(), f.vault, f.machineID,
		auditCtx{Actor: ActorAnonymous, Now: vaultNow}); err != nil {
		t.Fatalf("DisableMachine: %v", err)
	}

	// **secret は正しいものを渡す。** 間違った secret で試すと、disabled の
	// 検査が消えてもテストは通ってしまう(auth_test.go の同種の注意と同じ)。
	w := f.do(t, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: f.clientID, ClientSecret: f.secret})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %q)", w.Code, w.Body.String())
	}
	if got := decodeAPIError(t, w); got != "invalid_credentials" {
		t.Errorf("error = %q, want invalid_credentials (disabled must not be distinguishable)", got)
	}

	var detail string
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT detail FROM audit_logs WHERE action = ? AND result = ?`,
		string(ActionAuthMachine), string(ResultFailure),
	).Scan(&detail); err != nil {
		t.Fatalf("select audit row: %v", err)
	}
	if !strings.Contains(detail, `"reason":"`+ReasonDisabled+`"`) {
		t.Errorf("detail = %q, want reason = %q", detail, ReasonDisabled)
	}
}

// 認証成功で last_auth_at が入る(運用上「いつ最後に使われたか」を追える)。
func TestAPIAuthUpdatesLastAuthAt(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	f.token(t)

	machine, err := FindMachineByClientID(t.Context(), f.store.DB(), f.clientID)
	if err != nil {
		t.Fatalf("FindMachineByClientID: %v", err)
	}
	if machine.LastAuthAt == nil || !machine.LastAuthAt.Equal(vaultNow.UTC()) {
		t.Errorf("last_auth_at = %v, want %v", machine.LastAuthAt, vaultNow.UTC())
	}
}

// **sealed では 503 を返し、認証検証を実行しない**(M4 完了条件)。
func TestAPIAuthWhileSealed(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	f.vault.Seal(t.Context(), socketAudit(vaultNow))

	before := countAuditLogs(t, f.store.DB(), ActionAuthMachine)

	w := f.do(t, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: f.clientID, ClientSecret: f.secret})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %q)", w.Code, w.Body.String())
	}
	if got := decodeAPIError(t, w); got != "sealed" {
		t.Errorf("error = %q, want sealed", got)
	}
	// 検証が走っていないので、認証の監査も増えない。
	if after := countAuditLogs(t, f.store.DB(), ActionAuthMachine); after != before {
		t.Errorf("%d auth audit rows were written while sealed", after-before)
	}
}

// **監査 DB の障害時、認証は必ず拒否される**(fail closed)。
func TestAPIAuthFailsClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	breakAuditTable(t, f.store)

	w := f.do(t, http.MethodPost, "/v1/auth/token", "",
		authTokenRequest{ClientID: f.clientID, ClientSecret: f.secret})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %q)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Errorf("the response leaked a token: %q", w.Body.String())
	}
}

// ---- トークン ----

func TestAPIRejectsBadTokens(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	valid := f.token(t)

	// 生バイト列の 1 ビットを反転して、**確実に別の**トークンを作る。
	// 文字列置換(先頭文字を "A" に)だと、先頭がたまたま "A" のときに
	// 無置換となり、有効なトークンのままになる(base64url の先頭は毎回
	// ランダムなので確率的に落ちる)。
	rawValid, err := DecodeToken(valid)
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}
	flipped := base64Session(flipByte(rawValid, 0))

	tests := []struct {
		name   string
		header string
	}{
		{"missing", ""},
		{"not bearer", "Basic " + valid},
		{"empty bearer", "Bearer "},
		{"garbage", "Bearer not-a-token"},
		{"truncated", "Bearer " + valid[:len(valid)-1]},
		{"flipped", "Bearer " + flipped},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				secretsPath(testProjectSlug, testEnvSlug), nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()
			f.api.machineMux().ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body %q)", w.Code, w.Body.String())
			}
		})
	}
}

// **15 分後にトークンが無効になる**(M4 完了条件。Lookup の期限検査)。
func TestAPITokenExpires(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	// 期限内は通る。
	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusOK {
		t.Fatalf("before expiry = %d, want 200", w.Code)
	}

	// **sweep は動かさない。** 期限判定は Lookup が毎回行う(DESIGN §7.1)。
	f.api.now = func() time.Time { return vaultNow.Add(TokenTTL) }

	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("at expiry = %d, want 401", w.Code)
	}
}

// ---- 認可の再検査(DESIGN §4.5) ----
//
// **トークンは認証の証明であって、認可の証明ではない。** 発行後に状態が
// 変われば、既存のトークンでも即座に弾かれなければならない。

func TestAPIAuthorizationIsRecheckedPerRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// want は取り消し後に期待するステータスである。
		//
		// **401 と 403 の違いは、遮断が効く層の違いである。**
		// DisableMachine はトークンを削除する(C8)ので、そもそもトークンが
		// 見つからず 401 になる。grant 削除や論理削除はトークンを消さない
		// ため、認可の再検査(§4.5)で 403 になる。どちらも「既存トークンで
		// 即座に拒否される」ことに変わりはない。
		want   int
		revoke func(t *testing.T, f *apiFixture)
	}{
		{name: "machine disabled", want: http.StatusUnauthorized, revoke: func(t *testing.T, f *apiFixture) {
			if err := DisableMachine(t.Context(), f.vault, f.machineID,
				auditCtx{Actor: ActorAnonymous, Now: vaultNow}); err != nil {
				t.Fatalf("DisableMachine: %v", err)
			}
		}},
		// **トークンが残っていても disabled は効く。** DisableMachine を
		// 経由しない経路(直接の DB 更新)を模し、認可の再検査そのものを見る。
		// これが無いと「トークン削除に頼りきり」であることに気付けない。
		{name: "machine disabled without dropping tokens", want: http.StatusForbidden, revoke: func(t *testing.T, f *apiFixture) {
			if _, err := f.store.DB().ExecContext(t.Context(),
				`UPDATE machines SET disabled = 1 WHERE id = ?`, f.machineID); err != nil {
				t.Fatalf("disable machine: %v", err)
			}
		}},
		{name: "grant deleted", want: http.StatusForbidden, revoke: func(t *testing.T, f *apiFixture) {
			if _, err := f.store.DB().ExecContext(t.Context(),
				`DELETE FROM machine_grants WHERE machine_id = ?`, f.machineID); err != nil {
				t.Fatalf("delete grant: %v", err)
			}
		}},
		{name: "project soft deleted", want: http.StatusForbidden, revoke: func(t *testing.T, f *apiFixture) {
			if _, err := f.store.DB().ExecContext(t.Context(),
				`UPDATE projects SET deleted_at = ? WHERE id = ?`, vaultNow.Unix(), f.projectID); err != nil {
				t.Fatalf("delete project: %v", err)
			}
		}},
		{name: "environment soft deleted", want: http.StatusForbidden, revoke: func(t *testing.T, f *apiFixture) {
			if _, err := f.store.DB().ExecContext(t.Context(),
				`UPDATE environments SET deleted_at = ? WHERE id = ?`, vaultNow.Unix(), f.environmentID); err != nil {
				t.Fatalf("delete environment: %v", err)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newAPIFixture(t)
			token := f.token(t)

			// 取り消し前は読める。
			if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusOK {
				t.Fatalf("before revocation = %d, want 200", w.Code)
			}

			tt.revoke(t, f)

			// **既存のトークンでも即座に拒否される。**
			for _, path := range []string{
				secretsPath(testProjectSlug, testEnvSlug),
				"/v1/secrets/DATABASE_URL?project=myapp&env=prod",
			} {
				w := f.do(t, http.MethodGet, path, token, nil)
				if w.Code != tt.want {
					t.Fatalf("%s after revocation = %d, want %d (body %q)", path, w.Code, tt.want, w.Body.String())
				}
				// **理由を区別しない**(存在情報を漏らさない)。
				want := "forbidden"
				if tt.want == http.StatusUnauthorized {
					want = "invalid_token"
				}
				if got := decodeAPIError(t, w); got != want {
					t.Errorf("error = %q, want %q", got, want)
				}
			}
		})
	}
}

// grant の無い environment、存在しない environment、論理削除済み、不正な
// slug —— **全て同じ 403 に潰れる**(AGENTS.md ルール 54)。
func TestAPIForbiddenCasesAreIndistinguishable(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	// grant の無い environment を用意する。
	insertEnvironment(t, f.store.DB(), f.projectID, "stg", false)
	// 論理削除済みの project も用意する。
	deletedProject := insertProject(t, f.store.DB(), "archived", true)
	deletedEnv := insertEnvironment(t, f.store.DB(), deletedProject, "prod", false)
	f.grant(t, deletedEnv)

	paths := []string{
		secretsPath(testProjectSlug, "stg"),          // grant なし
		secretsPath("nope", "prod"),                  // 存在しない project
		secretsPath(testProjectSlug, "nope"),         // 存在しない environment
		secretsPath("archived", "prod"),              // project が論理削除済み
		secretsPath("Invalid_Slug", "prod"),          // 形式が不正
		"/v1/secrets?project=myapp",                  // env が無い
		"/v1/secrets/NOPE?project=myapp&env=prod",    // 存在しない key
		"/v1/secrets/bad-key?project=myapp&env=prod", // 形式が不正な key
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			w := f.do(t, http.MethodGet, path, token, nil)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %q)", w.Code, w.Body.String())
			}
			if got := decodeAPIError(t, w); got != "forbidden" {
				t.Errorf("error = %q, want forbidden", got)
			}
		})
	}
}

// 論理削除された project 配下の secret は取得できない(THREAT_MODEL §11.1)。
// **grant が残っていても** 取得できないことを確認する。
func TestAPIDeletedProjectHidesSecrets(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if _, err := f.store.DB().ExecContext(t.Context(),
		`UPDATE projects SET deleted_at = ? WHERE id = ?`, vaultNow.Unix(), f.projectID); err != nil {
		t.Fatalf("delete project: %v", err)
	}

	// grant は残したまま(削除の伝播に依存していないことの確認)。
	granted, err := HasGrant(t.Context(), f.store.DB(), f.machineID, f.environmentID)
	if err != nil {
		t.Fatalf("HasGrant: %v", err)
	}
	if !granted {
		t.Fatal("test setup: the grant was removed")
	}

	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// item を論理削除すると一覧からも単体取得からも消える。
func TestAPIDeletedItemIsNotReturned(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if _, err := f.store.DB().ExecContext(t.Context(),
		`UPDATE items SET deleted_at = ? WHERE key = ?`, vaultNow.Unix(), "API_TOKEN"); err != nil {
		t.Fatalf("delete item: %v", err)
	}

	w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp listSecretsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp.Secrets["API_TOKEN"]; ok {
		t.Error("a soft deleted item was returned")
	}
	if _, ok := resp.Secrets["DATABASE_URL"]; !ok {
		t.Error("a live item disappeared")
	}

	if w := f.do(t, http.MethodGet, "/v1/secrets/API_TOKEN?project=myapp&env=prod", token, nil); w.Code != http.StatusForbidden {
		t.Errorf("get deleted item = %d, want 403", w.Code)
	}
}

// ---- 監査 ----

// secret の読み取りは fail closed。記録できなければ値を返さない。
func TestAPISecretReadFailsClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)
	breakAuditTable(t, f.store)

	w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %q)", w.Code, w.Body.String())
	}
	// **平文が漏れていないこと。**
	if strings.Contains(w.Body.String(), "postgres://") {
		t.Errorf("the response leaked a secret: %q", w.Body.String())
	}
}

// H: authorize() を通過した後に seal が完了する競合窓では、復号が
// ErrSealed を返す。この場合は 500 ではなく **503**(SDK の ErrSealed
// マッピングに乗る)を返さなければならない。通常は seal 時にトークンを
// 全て消すため 401 になる、極小の窓を狙ったものである。
//
// 実際のリクエスト処理の途中で別ゴルーチンが seal するタイミングを狙うのは
// 非決定的なので、decryptAndRecord を直接呼び、既に sealed な Vault を渡して
// 「authorize は通ったが、復号する時点では sealed だった」状態を決定的に
// 再現する。
func TestAPIDecryptAndRecordReturns503WhenSealedRaceOccurs(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	f.vault.Seal(t.Context(), socketAudit(vaultNow))

	req := authorizedRequest{
		machineID:  f.machineID,
		remoteAddr: "10.0.0.2",
		now:        vaultNow,
		env: &EnvironmentRef{
			ProjectID: f.projectID, EnvironmentID: f.environmentID,
			ProjectSlug: testProjectSlug, EnvSlug: testEnvSlug,
		},
	}
	// sealed なら中身を見る前に WithDEK が ErrSealed を返すので、暗号文の
	// 中身は不要。
	secrets := []EncryptedSecret{{ItemID: 1, Key: "DATABASE_URL"}}

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		secretsPath(testProjectSlug, testEnvSlug), nil)

	values, ok := f.api.decryptAndRecord(w, r, req, secrets)
	if ok {
		t.Fatalf("decryptAndRecord succeeded while sealed: %v", values)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %q)", w.Code, w.Body.String())
	}
	if got := decodeAPIError(t, w); got != "sealed" {
		t.Errorf("error = %q, want %q", got, "sealed")
	}
}

// 監査ログに immutable ID と version が入る(THREAT_MODEL §10.2)。
func TestAPISecretReadAuditContents(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if w := f.do(t, http.MethodGet, "/v1/secrets/DATABASE_URL?project=myapp&env=prod", token, nil); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var (
		actor, target, detail  string
		projectID, envID       sql.NullInt64
		itemID, auditMachineID sql.NullInt64
		remote                 sql.NullString
	)
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT actor, target, target_project_id, target_environment_id, target_item_id,
		       target_machine_id, remote_addr, detail
		FROM audit_logs WHERE action = ?`, string(ActionSecretRead),
	).Scan(&actor, &target, &projectID, &envID, &itemID, &auditMachineID, &remote, &detail); err != nil {
		t.Fatalf("select audit row: %v", err)
	}

	if want := actorMachine(f.machineID); actor != want {
		t.Errorf("actor = %q, want %q", actor, want)
	}
	if target != "myapp/prod/DATABASE_URL" {
		t.Errorf("target = %q", target)
	}
	if !projectID.Valid || projectID.Int64 != f.projectID {
		t.Errorf("target_project_id = %v, want %d", projectID, f.projectID)
	}
	if !envID.Valid || envID.Int64 != f.environmentID {
		t.Errorf("target_environment_id = %v, want %d", envID, f.environmentID)
	}
	if !itemID.Valid {
		t.Error("target_item_id is NULL")
	}
	if !remote.Valid || remote.String != "10.0.0.2" {
		t.Errorf("remote_addr = %v, want the source ip", remote)
	}
	if !strings.Contains(detail, `"version":1`) {
		t.Errorf("detail = %q, want it to record the version", detail)
	}
	// **secret の値そのものは絶対に入らない**(THREAT_MODEL §10.6)。
	if strings.Contains(detail, "postgres") || strings.Contains(target, "postgres") {
		t.Error("the audit row contains the secret value")
	}
}

// ---- レート制限 ----

// **ランダムな client_id を大量に送っても、IP ベースの制限が効く**(M4 完了条件)。
func TestAPIRateLimitIsPerIPFirst(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)

	var lastCode int
	for i := range authTokenRatePerIP + 5 {
		// 毎回違う client_id を使う。第二段だけなら無制限に試行できてしまう。
		w := f.do(t, http.MethodPost, "/v1/auth/token", "",
			authTokenRequest{ClientID: fmt.Sprintf("client-%d", i), ClientSecret: "x"})
		lastCode = w.Code
		if i < authTokenRatePerIP && w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was rate limited too early", i+1)
		}
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("last status = %d, want 429", lastCode)
	}
}

// 第二段の client_id 制限も効く(1 つの credential への総当たりを鈍らせる)。
func TestAPIRateLimitPerClientID(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)

	for i := range authTokenRatePerClientID {
		// 送信元 IP を毎回変えて、第一段を回避する。
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/token",
			strings.NewReader(`{"client_id":"app-prod","client_secret":"x"}`))
		r.RemoteAddr = fmt.Sprintf("10.0.%d.%d:5000", i/250, i%250+1)
		w := httptest.NewRecorder()
		f.api.machineMux().ServeHTTP(w, r)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/token",
		strings.NewReader(`{"client_id":"app-prod","client_secret":"x"}`))
	r.RemoteAddr = "10.9.9.9:5000"
	w := httptest.NewRecorder()
	f.api.machineMux().ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 for a rate limited client id", w.Code)
	}
}

// ---- リクエストの検証 ----

func TestAPIAuthTokenRejectsBadBodies(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)

	tests := []struct {
		name string
		body string
	}{
		{"not json", "not json"},
		{"empty", ""},
		{"unknown field", `{"client_id":"app-prod","client_secret":"x","scope":"admin"}`},
		{"oversized", `{"client_id":"` + strings.Repeat("a", maxAuthTokenBody) + `"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/token",
				strings.NewReader(tt.body))
			r.RemoteAddr = "10.0.0.3:5000"
			w := httptest.NewRecorder()
			f.api.machineMux().ServeHTTP(w, r)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %q)", w.Code, w.Body.String())
			}
		})
	}
}

// **version パラメータは存在しない**(DESIGN §8.1)。指定しても無視され、
// 常に最新版が返る。
func TestAPIIgnoresVersionParameter(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	w := f.do(t, http.MethodGet, "/v1/secrets/DATABASE_URL?project=myapp&env=prod&version=1", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp getSecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Value != testSecretValue {
		t.Errorf("value = %q", resp.Value)
	}
}

// ---- 送信元 IP(レート制限のキー。ルール 35) ----

// **X-Forwarded-For を見ない**(api.go の remoteIP)。
//
// Machine API はリバースプロキシを介さず firewalld で到達制限する構成である
// (DESIGN §4.1)。ヘッダを信用した瞬間、第一段のレート制限のキーが
// 攻撃者制御の値になり、ヘッダを変えるだけで無制限に試行できる。
func TestRemoteIPIgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{name: "plain", remoteAddr: "10.0.0.2:53124", want: "10.0.0.2"},
		{name: "x-forwarded-for is ignored", remoteAddr: "10.0.0.2:53124",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4"}, want: "10.0.0.2"},
		{name: "x-real-ip is ignored", remoteAddr: "10.0.0.2:53124",
			headers: map[string]string{"X-Real-Ip": "1.2.3.4"}, want: "10.0.0.2"},
		{name: "forwarded is ignored", remoteAddr: "10.0.0.2:53124",
			headers: map[string]string{"Forwarded": "for=1.2.3.4"}, want: "10.0.0.2"},
		// **ポートはキーに含めない。** 含めると、接続ごとに別のバケットになり、
		// 送信元 IP による制限が事実上機能しなくなる。
		{name: "ipv6", remoteAddr: "[2001:db8::1]:53124", want: "2001:db8::1"},
		{name: "no port", remoteAddr: "10.0.0.2", want: "10.0.0.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
			r.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := remoteIP(r); got != tt.want {
				t.Errorf("remoteIP = %q, want %q", got, tt.want)
			}
		})
	}
}

// 第一段のバケットが **送信元ポートで分かれない**ことを、ハンドラ越しに確かめる。
//
// remoteIP の単体テストだけでは「ハンドラがそれを使っているか」は分からない。
// キーに RemoteAddr をそのまま渡す実装だと、接続ごとに新しいバケットになり、
// ここは永久に 429 にならない。
//
// **sealed な Vault で足りる**(制限は認証より手前で効く)。argon2 を払わない。
func TestAPIRateLimitBucketIgnoresTheSourcePort(t *testing.T) {
	t.Parallel()

	api := newMachineAPI(newSealedVault(t), discardLogger())
	api.now = func() time.Time { return vaultNow }

	send := func(t *testing.T, i int) int {
		t.Helper()

		// client_id は毎回変える(第二段ではなく第一段が効くことを見る)。
		body := fmt.Sprintf(`{"client_id":"client-%d","client_secret":"x"}`, i)
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/token",
			strings.NewReader(body))
		// 同じ IP、毎回違うポート。
		r.RemoteAddr = fmt.Sprintf("10.0.0.2:%d", 40000+i)
		w := httptest.NewRecorder()
		api.machineMux().ServeHTTP(w, r)
		return w.Code
	}

	for i := range authTokenRatePerIP {
		// sealed なので 503。制限には掛かっていない。
		if code := send(t, i); code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d = %d, want 503", i+1, code)
		}
	}
	if code := send(t, authTokenRatePerIP); code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429 (the bucket must be keyed by ip only)",
			authTokenRatePerIP+1, code)
	}
}

// 第二段(client_id)で拒否した試行は **監査に残る**。
//
// 拒否は確定しているが、「同じ client_id への総当たりが続いている」ことは
// 記録されなければ気付けない。生の client_id は入れず、subject_digest で相関を
// 取る(DESIGN §5.5)。
//
// **第一段(IP)の拒否は記録しない。** 未認証で到達できる口であり、記録すると
// 監査 DB への書き込みが攻撃者の投げた量に比例して増える。ここでは第二段の
// 挙動だけを固定する。
func TestAPIRateLimitedAttemptIsAudited(t *testing.T) {
	t.Parallel()

	v := newSealedVault(t)
	api := newMachineAPI(v, discardLogger())
	api.now = func() time.Time { return vaultNow }

	const clientID = "app-prod"
	send := func(t *testing.T, i int) int {
		t.Helper()

		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/auth/token",
			strings.NewReader(`{"client_id":"`+clientID+`","client_secret":"x"}`))
		// 送信元 IP を毎回変えて第一段を避ける。
		r.RemoteAddr = fmt.Sprintf("10.0.%d.%d:5000", i/250, i%250+1)
		w := httptest.NewRecorder()
		api.machineMux().ServeHTTP(w, r)
		return w.Code
	}

	for i := range authTokenRatePerClientID {
		if code := send(t, i); code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d = %d, want 503 (sealed)", i+1, code)
		}
	}
	if code := send(t, authTokenRatePerClientID); code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429", authTokenRatePerClientID+1, code)
	}

	var actor, result, detail string
	if err := v.db.QueryRowContext(t.Context(), `
		SELECT actor, result, detail FROM audit_logs WHERE action = ?`,
		string(ActionAuthMachine)).Scan(&actor, &result, &detail); err != nil {
		t.Fatalf("select the audit row for the rate limited attempt: %v", err)
	}
	if actor != ActorAnonymous || result != string(ResultFailure) {
		t.Errorf("actor/result = %q/%q, want anonymous/failure", actor, result)
	}
	if !strings.Contains(detail, ReasonRateLimited) {
		t.Errorf("detail = %q, want reason %q", detail, ReasonRateLimited)
	}
	if strings.Contains(detail, clientID) {
		t.Errorf("detail contains the raw client id: %q", detail)
	}
	if !strings.Contains(detail, subjectDigest(clientID)) {
		t.Errorf("detail = %q, want the subject digest", detail)
	}
}

// ---- 監査の順序と原子性 ----

// **result = success は「復号に成功した」後にしか書かれない**
// (THREAT_MODEL §10.5)。
//
// 記録してから復号する実装だと、返せなかった読み取りが success として残り、
// 「漏れたかもしれない値」の範囲を監査ログから正しく絞れなくなる。
func TestAPISecretReadIsNotAuditedWhenDecryptionFails(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	// 1 件だけ暗号文を壊す(AEAD なので復号は必ず失敗する)。
	var enc []byte
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT v.value_enc FROM item_versions v
		JOIN items i ON i.id = v.item_id WHERE i.key = 'DATABASE_URL'`).Scan(&enc); err != nil {
		t.Fatalf("read the ciphertext: %v", err)
	}
	if _, err := f.store.DB().ExecContext(t.Context(), `
		UPDATE item_versions SET value_enc = ? WHERE item_id =
			(SELECT id FROM items WHERE key = 'DATABASE_URL')`, flipByte(enc, 0)); err != nil {
		t.Fatalf("corrupt the ciphertext: %v", err)
	}

	for _, path := range []string{
		secretsPath(testProjectSlug, testEnvSlug),
		"/v1/secrets/DATABASE_URL?project=myapp&env=prod",
	} {
		w := f.do(t, http.MethodGet, path, token, nil)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("%s = %d, want 500 (body %q)", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "postgres://") || strings.Contains(w.Body.String(), "t0ken") {
			t.Errorf("%s leaked a secret: %q", path, w.Body.String())
		}
	}

	// **1 行も success が残っていないこと。** 一覧では健全な API_TOKEN の
	// 復号が先に通っているが、レスポンスは送られていないので記録もされない。
	if n := countAuditLogs(t, f.store.DB(), ActionSecretRead); n != 0 {
		t.Errorf("%d secret.read rows were written for reads that never returned", n)
	}
}

// **bulk fetch の監査は 1 トランザクションで N 行 INSERT される**
// (AGENTS.md ルール 23)。
//
// 件数を数えるだけでは「1 行ずつ commit する実装」と区別できない。途中の 1 行を
// 失敗させ、**先に成功した行まで巻き戻る**ことを見る。ここが分かれていると、
// 「半分だけ記録された読み取り」が残り、監査ログが実際の read 集合と一致しない。
func TestAPIBulkSecretReadAuditIsAtomic(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	// 一覧は key 昇順なので API_TOKEN → DATABASE_URL の順に INSERT される。
	// 2 行目だけを失敗させる。
	if _, err := f.store.DB().ExecContext(t.Context(), `
		CREATE TRIGGER fail_second_audit_row BEFORE INSERT ON audit_logs
		WHEN NEW.target = 'myapp/prod/DATABASE_URL'
		BEGIN SELECT RAISE(ABORT, 'audit write failed'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %q)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "postgres://") || strings.Contains(w.Body.String(), "t0ken") {
		t.Errorf("the response leaked a secret: %q", w.Body.String())
	}

	// **先に成功した API_TOKEN の行も残っていないこと。**
	if n := countAuditLogs(t, f.store.DB(), ActionSecretRead); n != 0 {
		t.Errorf("%d secret.read rows survived a partially failed batch, want 0 (all or nothing)", n)
	}
}

// secret が 1 件も無い environment でも 200 を返し、監査行は増えない。
//
// 「読み取った key ごとに 1 行」なので、0 件なら 0 行である。ここで 1 行
// 書いてしまうと、item を指さない secret.read が監査ログに混ざる。
func TestAPIListSecretsOnAnEmptyEnvironment(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	empty := insertEnvironment(t, f.store.DB(), f.projectID, "empty", false)
	f.grant(t, empty)

	w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, "empty"), token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", w.Code, w.Body.String())
	}
	var resp listSecretsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Secrets) != 0 {
		t.Errorf("secrets = %v, want empty", resp.Secrets)
	}
	if n := countAuditLogs(t, f.store.DB(), ActionSecretRead); n != 0 {
		t.Errorf("%d secret.read rows for an empty environment", n)
	}
}

// ---- /healthz ----

// **/healthz は sealed / unsealed を漏らさない**(AGENTS.md ルール 33)。
//
// 未認証で到達できる唯一の口である。応答が状態で変わると、攻撃者は
// 「いま unseal されている(= DEK がメモリにある)」ことを外から観測できる。
func TestAPIHealthzDoesNotRevealTheVaultState(t *testing.T) {
	t.Parallel()

	// unsealed 状態を argon2 なしで作る。ここで見たいのは応答の同一性である。
	unsealed := newSealedVault(t)
	unsealed.state = StateUnsealed
	unsealed.dekVersion = InitialDEKVersion

	probe := func(t *testing.T, v *Vault) *httptest.ResponseRecorder {
		t.Helper()

		api := newMachineAPI(v, discardLogger())
		api.now = func() time.Time { return vaultNow }
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
		r.RemoteAddr = "10.0.0.2:53124"
		api.machineMux().ServeHTTP(w, r)
		return w
	}

	sealedResp := probe(t, newSealedVault(t))
	unsealedResp := probe(t, unsealed)

	if sealedResp.Code != http.StatusOK || unsealedResp.Code != http.StatusOK {
		t.Fatalf("status = %d (sealed) / %d (unsealed), want 200 for both",
			sealedResp.Code, unsealedResp.Code)
	}
	if sealedResp.Body.String() != unsealedResp.Body.String() {
		t.Errorf("bodies differ: %q (sealed) vs %q (unsealed)",
			sealedResp.Body.String(), unsealedResp.Body.String())
	}
	if fmt.Sprint(sealedResp.Header()) != fmt.Sprint(unsealedResp.Header()) {
		t.Errorf("headers differ: %v (sealed) vs %v (unsealed)",
			sealedResp.Header(), unsealedResp.Header())
	}
	// 認証は不要である(トークンを付けずに 200 が返っている)。
	if got := sealedResp.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// **失敗した読み取りも監査される**(AGENTS.md ルール 22「read も、失敗も」)。
//
// 認証済みの主体が拒否されたことは、grant の設定ミスと探索行為の両方の
// 手掛かりになる。**対象は記録しない** ── 拒否された時点で、要求された
// project / env が実在するかは確定しておらず、記録すれば存在情報が監査ログ
// 経由で漏れる。
func TestAPIDeniedSecretReadIsAudited(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if _, err := f.store.DB().ExecContext(t.Context(),
		`DELETE FROM machine_grants WHERE machine_id = ?`, f.machineID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}

	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}

	var (
		actor, result, detail string
		target                sql.NullString
		projectID, envID      sql.NullInt64
	)
	if err := f.store.DB().QueryRowContext(t.Context(), `
		SELECT actor, result, target, target_project_id, target_environment_id, detail
		FROM audit_logs WHERE action = ? AND result = ?`,
		string(ActionSecretRead), string(ResultFailure),
	).Scan(&actor, &result, &target, &projectID, &envID, &detail); err != nil {
		t.Fatalf("select audit row: %v", err)
	}

	if want := actorMachine(f.machineID); actor != want {
		t.Errorf("actor = %q, want %q", actor, want)
	}
	if !strings.Contains(detail, ReasonForbidden) {
		t.Errorf("detail = %q, want it to contain %q", detail, ReasonForbidden)
	}
	// **対象は入らない。**
	if target.Valid {
		t.Errorf("target = %v, want NULL for a denied request", target)
	}
	if projectID.Valid || envID.Valid {
		t.Errorf("target ids = %v/%v, want NULL for a denied request", projectID, envID)
	}
}

// **トークンが無効な場合は監査しない。**
//
// actor が特定できず、この経路にはレート制限も無いため、記録すると未認証の
// トラフィックだけで監査 DB を膨らませられる。
func TestAPIInvalidTokenIsNotAudited(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	before := countAuditLogs(t, f.store.DB(), ActionSecretRead)

	for range 5 {
		if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), "not-a-token", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	}

	if after := countAuditLogs(t, f.store.DB(), ActionSecretRead); after != before {
		t.Errorf("%d audit rows were written for unauthenticated requests", after-before)
	}
}

// 拒否の監査が書けなければ 500 にする(fail closed)。
// 「記録されない secret へのアクセス」を残さない。
func TestAPIDeniedSecretReadFailsClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	f := newAPIFixture(t)
	token := f.token(t)

	if _, err := f.store.DB().ExecContext(t.Context(),
		`DELETE FROM machine_grants WHERE machine_id = ?`, f.machineID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	breakAuditTable(t, f.store)

	if w := f.do(t, http.MethodGet, secretsPath(testProjectSlug, testEnvSlug), token, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %q)", w.Code, w.Body.String())
	}
}
