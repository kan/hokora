package main

import (
	"encoding/base64"
	"errors"
	"testing"
)

// newMachineForAuth は認証テスト用の machine を 1 台作る。
//
// **argon2 を一切使わない**(Machine API の認証は SHA-256 である。
// AGENTS.md ルール 7)。Vault も keyring も要らないので、DB だけを用意する。
func newMachineForAuth(t *testing.T, clientID string, disabled bool) (*Store, string) {
	t.Helper()

	store := newTestStore(t)
	id, secret, err := CreateMachine(t.Context(), store.DB(), clientID, "test machine",
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	if disabled {
		if _, err := store.DB().ExecContext(t.Context(),
			`UPDATE machines SET disabled = 1 WHERE id = ?`, id); err != nil {
			t.Fatalf("disable machine: %v", err)
		}
	}
	return store, secret
}

// dummySecretPreimage は dummySecretHash の元になっている文字列である。
//
// **これを client_secret として送ると、存在しない client_id に対する比較が
// 一致する。** 実装が「比較が通ったら machine を返す」だけになっていると、
// ここで nil の machine を返す(あるいは nil 参照で落ちる)。
// 比較結果とは独立に machine の存在を確かめていることを、この値で固定する。
//
//nolint:gosec // G101: 認証情報ではなく、dummy hash の原像である
const dummySecretPreimage = "hokora/dummy-secret/v1"

func TestVerifyMachineCredentials(t *testing.T) {
	t.Parallel()

	const clientID = "app-prod"

	tests := []struct {
		name string
		// secret が空のときは、生成された **正しい** secret を使う。
		// 「secret は合っているのに拒否される」ケースを弱く書かないための既定である。
		secret   string
		clientID string
		disabled bool
		wantErr  error
	}{
		{name: "valid credentials", clientID: clientID},
		{name: "wrong secret", clientID: clientID, secret: "not-the-secret", wantErr: ErrInvalidCredentials},
		{name: "unknown client id", clientID: "does-not-exist", secret: "whatever", wantErr: ErrInvalidCredentials},
		// client_id が空でも、正しい secret を添えて通ってはならない。
		{name: "empty client id", clientID: "", wantErr: ErrInvalidCredentials},
		// **disabled は内部的に errMachineDisabled を返す**(監査 detail 用)。
		// HTTP 応答は verifyForToken が invalid_credentials に潰すので区別は
		// 漏れない(そちらは handler レベルのテストで固定する)。
		// **secret は正しいものを渡す。** 間違った secret で試すと、disabled の
		// 検査が消えてもテストは通ってしまう。
		{name: "disabled machine", clientID: clientID, disabled: true, wantErr: errMachineDisabled},
		// **dummy hash の原像を送っても、存在しない client_id は通らない。**
		// 比較の成否だけで分岐する実装をここで落とす。
		{name: "dummy hash preimage against an unknown client id",
			clientID: "does-not-exist", secret: dummySecretPreimage, wantErr: ErrInvalidCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, generated := newMachineForAuth(t, clientID, tt.disabled)
			secret := tt.secret
			if secret == "" {
				secret = generated
			}

			machine, err := verifyMachineCredentials(t.Context(), store.DB(), tt.clientID, secret)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				if machine != nil {
					t.Errorf("machine = %+v, want nil on failure", machine)
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyMachineCredentials: %v", err)
			}
			if machine == nil || machine.ClientID != tt.clientID {
				t.Fatalf("machine = %+v, want the machine for %q", machine, tt.clientID)
			}
		})
	}
}

// **存在しない client_id でも同じだけ比較を行う**(AGENTS.md ルール 21)。
//
// 応答時間そのものは計測が不安定なので測らない。代わりに、比較が同じ形で
// 行われるための前提を固定する: dummy hash が実際の secret_hash と同じ長さで
// あること。長さが違うと ConstantTimeCompare は中身を見ずに戻り、そこに
// 「その client_id は存在しない」という差が出る(ratelimit.go の
// constantTimeEqual のコメント参照)。
func TestDummySecretHashHasTheSameShapeAsARealHash(t *testing.T) {
	t.Parallel()

	realHash := hashClientSecret("some-client-secret")
	if len(dummySecretHash) != len(realHash) {
		t.Fatalf("len(dummySecretHash) = %d, want %d (a length mismatch short-circuits the comparison)",
			len(dummySecretHash), len(realHash))
	}
	// 万一 dummy が実在の secret のハッシュと一致すると、その secret で
	// 存在しない client_id が「認証できる」経路が生まれる。原像を固定する。
	if got := hashClientSecret(dummySecretPreimage); string(got) != string(dummySecretHash[:]) {
		t.Error("dummySecretHash is not the hash of its documented preimage")
	}
}

// client_secret は **サーバーが crypto/rand で生成したものに限る**
// (AGENTS.md ルール 8)。生成物の性質を固定する。
func TestGenerateClientSecret(t *testing.T) {
	t.Parallel()

	encoded, hash, err := GenerateClientSecret()
	if err != nil {
		t.Fatalf("GenerateClientSecret: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("the generated secret is not base64url: %v", err)
	}
	if len(raw) != ClientSecretBytes {
		t.Errorf("secret = %d bytes, want %d", len(raw), ClientSecretBytes)
	}

	// **ハッシュは「クライアントが提示する文字列」に対して取る。** 生バイト列に
	// 対して取ると、検証側と食い違って正しい credential でも認証が通らない。
	if string(hash) != string(hashClientSecret(encoded)) {
		t.Error("the stored hash does not match the hash of the encoded secret")
	}

	other, _, err := GenerateClientSecret()
	if err != nil {
		t.Fatalf("GenerateClientSecret: %v", err)
	}
	if other == encoded {
		t.Error("two generated secrets are identical")
	}
}

// **machine の作成は fail closed**(AGENTS.md ルール 26)。監査が書けなければ
// machine 行も残さない。残ると「作成の記録がない machine」が生まれる。
func TestCreateMachineFailsClosedWhenAuditIsBroken(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	breakAuditTable(t, store)

	_, secret, err := CreateMachine(t.Context(), store.DB(), "app-prod", "app server",
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if err == nil {
		t.Fatal("CreateMachine succeeded even though the audit log could not be written")
	}
	if secret != "" {
		t.Error("CreateMachine returned a secret for a machine it did not create")
	}

	// **トランザクションごと巻き戻っていること。**
	var n int
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM machines`).Scan(&n); err != nil {
		t.Fatalf("count machines: %v", err)
	}
	if n != 0 {
		t.Errorf("%d machine rows survived a failed audit", n)
	}
}

// **CreateMachine は名前をサーバー側で検証する**(#7)。空の名前は弾き、
// machine 行を 1 つも残さない(検証は crypto/rand の消費より前)。
func TestCreateMachineRejectsAnEmptyName(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)

	_, secret, err := CreateMachine(t.Context(), store.DB(), "app-prod", "  ",
		auditCtx{Actor: ActorAnonymous, Now: vaultNow})
	if !errors.Is(err, errMachineNameEmpty) {
		t.Fatalf("error = %v, want errMachineNameEmpty", err)
	}
	if secret != "" {
		t.Error("a secret was returned for a machine that was not created")
	}
	var n int
	if err := store.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM machines`).Scan(&n); err != nil {
		t.Fatalf("count machines: %v", err)
	}
	if n != 0 {
		t.Errorf("%d machine rows were created for an invalid name", n)
	}
}

// **CreateMachineWithGrant は machine 作成と grant 付与を 1 トランザクションに
// まとめる**(#9)。成功すれば両方の監査が残り、grant が効く。grant 付与が
// 失敗すれば machine 行ごと巻き戻る(credential を見せた権限なし machine を
// 残さない)。
func TestCreateMachineWithGrant(t *testing.T) {
	t.Parallel()

	ac := auditCtx{Actor: ActorAnonymous, Now: vaultNow}

	countMachines := func(t *testing.T, store *Store) int {
		t.Helper()
		var n int
		if err := store.DB().QueryRowContext(t.Context(),
			`SELECT COUNT(*) FROM machines`).Scan(&n); err != nil {
			t.Fatalf("count machines: %v", err)
		}
		return n
	}

	t.Run("success creates the machine and grant atomically", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		projectID := insertProject(t, store.DB(), testProjectSlug, false)
		envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, false)

		id, secret, err := CreateMachineWithGrant(t.Context(), store.DB(), "app-prod", "請求バッチ", envID, ac)
		if err != nil {
			t.Fatalf("CreateMachineWithGrant: %v", err)
		}
		if id <= 0 {
			t.Fatalf("machine id = %d, want a positive row id", id)
		}
		// **secret はサーバー生成の base64url**(ルール 8)。往復で使える形。
		if _, decErr := base64.RawURLEncoding.DecodeString(secret); decErr != nil {
			t.Errorf("the returned secret is not base64url: %v", decErr)
		}

		granted, err := HasGrant(t.Context(), store.DB(), id, envID)
		if err != nil {
			t.Fatalf("HasGrant: %v", err)
		}
		if !granted {
			t.Error("the grant was not created")
		}

		// **両方の監査が残る。**
		if got := countAuditLogs(t, store.DB(), ActionMachineCreate); got != 1 {
			t.Errorf("%d machine.create audit rows, want 1", got)
		}
		if got := countAuditLogs(t, store.DB(), ActionGrantCreate); got != 1 {
			t.Errorf("%d grant.create audit rows, want 1", got)
		}
	})

	t.Run("a nonexistent environment leaves no machine behind", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		insertProject(t, store.DB(), testProjectSlug, false)

		_, secret, err := CreateMachineWithGrant(t.Context(), store.DB(), "app-prod", "請求バッチ", 999999, ac)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound", err)
		}
		if secret != "" {
			t.Error("a secret was returned for a machine that was rolled back")
		}
		// **machine 行が巻き戻っていること**(grant 付与失敗で machine を残さない)。
		if n := countMachines(t, store); n != 0 {
			t.Errorf("%d machine rows survived a failed grant", n)
		}
		if got := countAuditLogs(t, store.DB(), ActionMachineCreate); got != 0 {
			t.Errorf("%d machine.create audit rows survived the rollback, want 0", got)
		}
	})

	t.Run("a soft-deleted environment leaves no machine behind", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		projectID := insertProject(t, store.DB(), testProjectSlug, false)
		envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, true) // deleted_at 設定済み

		_, _, err := CreateMachineWithGrant(t.Context(), store.DB(), "app-prod", "請求バッチ", envID, ac)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound (a soft-deleted environment must be treated as absent)", err)
		}
		if n := countMachines(t, store); n != 0 {
			t.Errorf("%d machine rows survived a grant to a deleted environment", n)
		}
	})

	t.Run("an invalid name is rejected before any row", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		projectID := insertProject(t, store.DB(), testProjectSlug, false)
		envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, false)

		_, secret, err := CreateMachineWithGrant(t.Context(), store.DB(), "app-prod", "", envID, ac)
		if !errors.Is(err, errMachineNameEmpty) {
			t.Fatalf("error = %v, want errMachineNameEmpty", err)
		}
		if secret != "" {
			t.Error("a secret was returned for an invalid name")
		}
		if n := countMachines(t, store); n != 0 {
			t.Errorf("%d machine rows were created for an invalid name", n)
		}
	})
}

// 存在しない machine への revoke は ErrNotFound になる。
//
// **UPDATE が 0 行に当たったことを「成功」と扱うと、無効化したつもりの
// machine が生き続ける。** 緊急遮断操作でこれが起きると、遮断の失敗に
// 気付けない。
func TestRevokeMachineRequiresAnExistingRow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		revoke func(t *testing.T, v *Vault) error
	}{
		{"disable", func(t *testing.T, v *Vault) error {
			return DisableMachine(t.Context(), v, 4242, auditCtx{Actor: ActorAnonymous, Now: vaultNow})
		}},
		{"rotate_secret", func(t *testing.T, v *Vault) error {
			secret, err := RotateMachineSecret(t.Context(), v, 4242, auditCtx{Actor: ActorAnonymous, Now: vaultNow})
			if err == nil && secret != "" {
				t.Error("a secret was returned for a machine that does not exist")
			}
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// 鍵は要らない(revoke は DB 更新とトークン削除だけである)。
			v := newSealedVault(t)
			if err := tt.revoke(t, v); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
		})
	}
}

// GenerateClientID は slug として有効な、毎回異なる値を返す。
//
// **slug 制約に収まること**が重要である。ここが破れると、生成した client_id が
// project slug 等と同じ検証を通らず、作成した machine を後段で扱えなくなる。
func TestGenerateClientID(t *testing.T) {
	t.Parallel()

	const iterations = 128
	seen := make(map[string]struct{}, iterations)
	for i := range iterations {
		id, err := GenerateClientID()
		if err != nil {
			t.Fatalf("GenerateClientID #%d: %v", i, err)
		}
		if len(id) != clientIDLen {
			t.Fatalf("length = %d, want %d", len(id), clientIDLen)
		}
		// **slug として通ること。** UI が ValidateSlug を通すのと同じ検証。
		if err := ValidateSlug(id); err != nil {
			t.Fatalf("GenerateClientID produced an invalid slug %q: %v", id, err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("GenerateClientID repeated %q", id)
		}
		seen[id] = struct{}{}
	}
}
