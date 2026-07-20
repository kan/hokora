package main

import (
	"database/sql"
	"testing"
	"time"
)

// maxUint32 / overUint32 は item_versions / keyring の CHECK 制約が守る境界である。
// itemAAD (M2) はこれらのカラムを uint32 に変換するため、境界を 1 つでも
// 見誤ると、範囲外の値が AAD の型変換で静かに壊れる。
const (
	maxUint32  = 4294967295
	overUint32 = 4294967296
)

// requireEnvironment は items テーブルの外部キーが要求する environment を
// 用意し、その ID を返す。insertProject / insertEnvironment (store_test.go) を
// そのまま使い、両者を束ねるだけの薄いラッパーに留める。
func requireEnvironment(t *testing.T, db *sql.DB, slug string) int64 {
	t.Helper()

	projectID := insertProject(t, db, slug, false)
	if _, err := insertEnvironmentErr(t, db, projectID, slug, false); err != nil {
		t.Fatalf("insert environment: %v", err)
	}

	var id int64
	err := db.QueryRowContext(t.Context(),
		`SELECT id FROM environments WHERE project_id = ? AND slug = ?`, projectID, slug,
	).Scan(&id)
	if err != nil {
		t.Fatalf("select environment id: %v", err)
	}
	return id
}

func insertItem(t *testing.T, db *sql.DB, environmentID int64, key string, currentVersion int64) error {
	t.Helper()

	now := time.Now().Unix()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO items (environment_id, key, current_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		environmentID, key, currentVersion, now, now,
	)
	return err
}

// items.current_version は 0 以上(未作成のバージョンを表す)を許すが、
// item_versions.version は 1 始まりで 0 を許さない。境界を混同すると、
// 一方の制約がもう一方に漏れて検査の意味を失う。
func TestItemsCurrentVersionCheckConstraint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value int64
		ok    bool
	}{
		{"zero is the not-yet-created marker", 0, true},
		{"typical", 3, true},
		{"max uint32", maxUint32, true},

		{"negative", -1, false},
		{"over uint32", overUint32, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newTestStore(t)
			environmentID := requireEnvironment(t, store.DB(), "proj")

			err := insertItem(t, store.DB(), environmentID, "KEY", tt.value)
			if tt.ok && err != nil {
				t.Errorf("insert items.current_version = %d: %v, want nil", tt.value, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("insert items.current_version = %d succeeded, want the CHECK constraint to reject it", tt.value)
			}
		})
	}
}

func insertItemVersion(t *testing.T, db *sql.DB, itemID, version, dekVersion int64) error {
	t.Helper()

	now := time.Now().Unix()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO item_versions (item_id, version, value_enc, nonce, dek_version, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		itemID, version, []byte("ciphertext"), []byte("nonce"), dekVersion, now, "user:1",
	)
	return err
}

// item_versions.version は 1 始まりで、items.current_version と違って 0 を
// 許さない(バージョン番号として 0 は「未作成」を意味し、実在の行には
// なり得ない)。
func TestItemVersionsVersionCheckConstraint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value int64
		ok    bool
	}{
		{"min valid", 1, true},
		{"max uint32", maxUint32, true},

		{"zero", 0, false},
		{"negative", -1, false},
		{"over uint32", overUint32, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newTestStore(t)
			environmentID := requireEnvironment(t, store.DB(), "proj")
			if err := insertItem(t, store.DB(), environmentID, "KEY", 0); err != nil {
				t.Fatalf("insert item: %v", err)
			}

			err := insertItemVersion(t, store.DB(), 1, tt.value, 1)
			if tt.ok && err != nil {
				t.Errorf("insert item_versions.version = %d: %v, want nil", tt.value, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("insert item_versions.version = %d succeeded, want the CHECK constraint to reject it", tt.value)
			}
		})
	}
}

// dek_version は item_versions / keyring の両方に現れ、どちらも同じ範囲
// (1..uint32 max)を守る。ここでは item_versions 側を確認する。
func TestItemVersionsDekVersionCheckConstraint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value int64
		ok    bool
	}{
		{"min valid", 1, true},
		{"max uint32", maxUint32, true},

		{"zero", 0, false},
		{"negative", -1, false},
		{"over uint32", overUint32, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newTestStore(t)
			environmentID := requireEnvironment(t, store.DB(), "proj")
			if err := insertItem(t, store.DB(), environmentID, "KEY", 0); err != nil {
				t.Fatalf("insert item: %v", err)
			}

			err := insertItemVersion(t, store.DB(), 1, 1, tt.value)
			if tt.ok && err != nil {
				t.Errorf("insert item_versions.dek_version = %d: %v, want nil", tt.value, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("insert item_versions.dek_version = %d succeeded, want the CHECK constraint to reject it", tt.value)
			}
		})
	}
}

func insertKeyring(t *testing.T, db *sql.DB, id, dekVersion int64) error {
	t.Helper()

	now := time.Now().Unix()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO keyring (id, dek_wrapped, dek_nonce, kdf_salt, dek_version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, []byte("wrapped"), []byte("nonce"), []byte("salt"), dekVersion, now, now,
	)
	return err
}

// keyring は常に単一行(id = 1)でなければならない。CHECK(id = 1) が抜けると
// 複数の DEK が並存しうる状態になり、どれが有効な鍵か区別できなくなる。
func TestKeyringAllowsOnlyASingleRow(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	db := store.DB()

	if err := insertKeyring(t, db, 1, 1); err != nil {
		t.Fatalf("insert the first keyring row: %v", err)
	}
	if err := insertKeyring(t, db, 1, 2); err == nil {
		t.Error("inserted a second row with id = 1; the primary key does not prevent duplicates")
	}
	if err := insertKeyring(t, db, 2, 1); err == nil {
		t.Error("inserted a keyring row with id != 1; CHECK(id = 1) is not in effect")
	}
}

// keyring.dek_version は item_versions.dek_version と同じ範囲を守る。
// 別テーブルの制約なので、片方を直してもう片方に反映し忘れる事故を検出する。
func TestKeyringDekVersionCheckConstraint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value int64
		ok    bool
	}{
		{"min valid", 1, true},
		{"max uint32", maxUint32, true},

		{"zero", 0, false},
		{"negative", -1, false},
		{"over uint32", overUint32, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newTestStore(t)
			err := insertKeyring(t, store.DB(), 1, tt.value)
			if tt.ok && err != nil {
				t.Errorf("insert keyring.dek_version = %d: %v, want nil", tt.value, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("insert keyring.dek_version = %d succeeded, want the CHECK constraint to reject it", tt.value)
			}
		})
	}
}
