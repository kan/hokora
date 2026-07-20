package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func assertUserVersion(t *testing.T, db *sql.DB, want int) {
	t.Helper()

	var got int
	if err := db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&got); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if got != want {
		t.Errorf("user_version = %d, want %d", got, want)
	}
}

func TestMigrateSetsUserVersion(t *testing.T) {
	t.Parallel()

	assertUserVersion(t, newTestStore(t).DB(), schemaVersion)
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	store := newTestStore(t) // 1 回目は newTestStore 内で適用済み

	if err := Migrate(t.Context(), store.DB()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

// バイナリより新しいスキーマの DB は移行しない。知らないカラムを無視したまま
// 書き込むと、データを壊したうえに気付けない。
func TestMigrateRejectsUnknownSchema(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	if _, err := store.DB().ExecContext(t.Context(),
		fmt.Sprintf("PRAGMA user_version = %d", schemaVersion+1)); err != nil {
		t.Fatalf("bump user_version: %v", err)
	}

	if err := Migrate(t.Context(), store.DB()); err == nil {
		t.Fatal("migrated a database whose schema version is unknown to the binary")
	}
}

// スキーマのバージョン検査は「移行するとき」ではなく「開くとき」に効く。
// serve / unseal / get は移行しないので、Migrate 側だけの検査では素通りする。
func TestOpenStoreRejectsMismatchedSchema(t *testing.T) {
	t.Parallel()

	t.Run("uninitialized", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "empty.db")
		store, err := openDatabase(t.Context(), path)
		if err != nil {
			t.Fatalf("openDatabase: %v", err)
		}
		store.Close()

		if _, err := OpenStore(t.Context(), path); err == nil {
			t.Fatal("opened a database with no schema applied")
		}
	})

	t.Run("newer schema", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "newer.db")
		store := newTestStoreAt(t, path)
		if _, err := store.DB().ExecContext(t.Context(),
			fmt.Sprintf("PRAGMA user_version = %d", schemaVersion+1)); err != nil {
			t.Fatalf("bump user_version: %v", err)
		}

		if _, err := OpenStore(t.Context(), path); err == nil {
			t.Fatal("opened a database whose schema version is unknown to the binary")
		}
	})
}

func TestMigrateCreatesAllTables(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)

	want := []string{
		"audit_logs", "environments", "item_versions", "items",
		"keyring", "machine_grants", "machines", "projects", "sessions", "users",
	}
	for _, table := range want {
		var name string
		err := store.DB().QueryRowContext(t.Context(),
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %s: %v", table, err)
		}
	}
}

func TestCmdInitIsRepeatable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sub", "hokora.db")

	for i := range 2 {
		if err := cmdInit(t.Context(), []string{"-db", path}); err != nil {
			t.Fatalf("cmdInit (run %d): %v", i+1, err)
		}
	}

	store, err := OpenStore(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()

	assertUserVersion(t, store.DB(), schemaVersion)
}

// -h は usage の要求であって失敗ではない。エラーを返すと終了コードが 1 になり、
// 呼び出し側のスクリプトが失敗と区別できない。
func TestCmdInitFlagErrors(t *testing.T) {
	t.Parallel()

	if err := cmdInit(t.Context(), []string{"-h"}); err != nil {
		t.Errorf("cmdInit -h = %v, want nil", err)
	}
	if err := cmdInit(t.Context(), []string{"-nonexistent"}); err == nil {
		t.Error("cmdInit accepted an unknown flag")
	}
}

// 余分な位置引数は、フラグとして解釈されなかった入力の取りこぼしを示す。
// 黙って無視すると、"-db path extra-typo" のような打ち間違いに気付けない。
func TestCmdInitRejectsExtraPositionalArgs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hokora.db")
	if err := cmdInit(t.Context(), []string{"-db", path, "extra"}); err == nil {
		t.Error("cmdInit accepted an unexpected positional argument")
	}
}

// DB とその付随ファイルは所有者以外から読めてはならない。
//
// 「SQLite は WAL / SHM を本体と同じモードで作る」という前提の上に、DB ファイル
// だけを先に 0600 で作る実装が乗っている。前提が成り立つことをコメントで主張する
// だけにせず、実際のファイルモードで確認する。
func TestCmdInitCreatesPrivateFiles(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "lib")
	path := filepath.Join(dir, "hokora.db")
	if err := cmdInit(t.Context(), []string{"-db", path}); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	assertMode(t, dir, dbDirMode)
	assertMode(t, path, dbFileMode)

	// WAL / SHM は書き込みが起きて初めて現れるため、接続を開いて 1 行書く。
	store, err := OpenStore(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()
	insertProject(t, store.DB(), "web-2", false)

	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Fatalf("expected %s to exist: %v", path+suffix, err)
		}
		assertMode(t, path+suffix, dbFileMode)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %v, want %v", path, got, want)
	}
}
