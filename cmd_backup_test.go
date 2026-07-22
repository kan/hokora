package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// runBackup は cmdBackup を実行し、stdout / stderr を捕捉して返す。
//
// cmdBackup は os.Stdout / os.Stderr に書くため、captureOutput を使うテストは
// t.Parallel() を呼ばない(main_test.go の captureOutput のコメント参照)。
func runBackup(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	stdout, stderr = captureOutput(t, func() {
		err = cmdBackup(t.Context(), args)
	})
	return stdout, stderr, err
}

// openReadOnly はバックアップを読み取り専用で開く(随伴ファイルを作らせない)。
func openReadOnly(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dataSourceNameReadOnly(path))
	if err != nil {
		t.Fatalf("open backup read-only: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestBackupCopiesCiphertextWhileSourceIsOpen は、稼働中(ハンドルを開いたまま)
// の DB からバックアップが取れ、コミット済みのデータが取り込まれることを確認する。
// これが offline 手順(停止 → tar)を置き換えるオンライン性の核心である。
func TestBackupCopiesCiphertextWhileSourceIsOpen(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	// newTestStoreAt はスキーマ適用済みの store を開いたまま(t.Cleanup で Close)
	// 保持する。これで「サーバー稼働中」に相当する並行アクセス状況を作る。
	store := newTestStoreAt(t, src)
	insertProject(t, store.DB(), "web", false)

	dst := filepath.Join(t.TempDir(), "backup", "hokora.bak.db")
	stdout, stderr, err := runBackup(t, "--db", src, "--out", dst)
	if err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	// stdout はパスだけ(スクリプトがパスを拾える)。注意書きは stderr。
	if got := strings.TrimSpace(stdout); got != dst {
		t.Errorf("stdout = %q, want just the path %q", got, dst)
	}
	if !strings.Contains(stderr, "master key") {
		t.Errorf("stderr = %q, want a reminder about the master key", stderr)
	}

	// バックアップに元データが入っていること。
	backup := openReadOnly(t, dst)
	var slug string
	if err := backup.QueryRowContext(t.Context(),
		`SELECT slug FROM projects WHERE slug = 'web'`).Scan(&slug); err != nil {
		t.Fatalf("read project from backup: %v", err)
	}
	if slug != "web" {
		t.Errorf("backup project slug = %q, want %q", slug, "web")
	}
}

// TestBackupWorksWithoutKeyring は、keyring の無い DB でもバックアップが取れる
// ことを確認する。backup が Vault / DEK / MK に一切依存しない(暗号文をそのまま
// コピーするだけ)ことの証拠になる。
func TestBackupWorksWithoutKeyring(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	newTestStoreAt(t, src) // スキーマのみ。keyring も admin も作らない。

	dst := filepath.Join(t.TempDir(), "hokora.bak.db")
	if _, _, err := runBackup(t, "--db", src, "--out", dst); err != nil {
		t.Fatalf("cmdBackup without keyring: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("backup not created: %v", err)
	}
}

// TestBackupFilePermsAndNoSidecars は、生成物が 0600 で、`-wal` / `-shm` の
// 随伴ファイルを残さない単一ファイルであることを確認する。
func TestBackupFilePermsAndNoSidecars(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	newTestStoreAt(t, src)

	dst := filepath.Join(t.TempDir(), "hokora.bak.db")
	if _, _, err := runBackup(t, "--db", src, "--out", dst); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if perm := info.Mode().Perm(); perm != dbFileMode {
		t.Errorf("backup perm = %04o, want %04o", perm, dbFileMode)
	}
	for _, sidecar := range []string{dst + "-wal", dst + "-shm", dst + "-journal"} {
		if _, err := os.Stat(sidecar); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("unexpected sidecar %s exists (err=%v)", sidecar, err)
		}
	}
}

// TestBackupParentDirIsPrivate は、作成した親ディレクトリが 0700 であることを
// 確認する(バックアップは全 secret の暗号文を含むため)。
func TestBackupParentDirIsPrivate(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	newTestStoreAt(t, src)

	parent := filepath.Join(t.TempDir(), "backups")
	dst := filepath.Join(parent, "hokora.bak.db")
	if _, _, err := runBackup(t, "--db", src, "--out", dst); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if perm := info.Mode().Perm(); perm != dbDirMode {
		t.Errorf("parent dir perm = %04o, want %04o", perm, dbDirMode)
	}
}

// TestBackupRefusesToOverwrite は、既存の出力先を上書きしないことを確認する。
// バックアップを取り違えて既存のバックアップを潰す事故を防ぐ。
func TestBackupRefusesToOverwrite(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	newTestStoreAt(t, src)

	dst := filepath.Join(t.TempDir(), "exists.db")
	const sentinel = "do not clobber"
	if err := os.WriteFile(dst, []byte(sentinel), 0o600); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}

	_, _, err := runBackup(t, "--db", src, "--out", dst)
	if err == nil {
		t.Fatal("cmdBackup overwrote an existing file, want an error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v, want it to mention that the file already exists", err)
	}
	// 既存ファイルは無傷であること。
	got, err := os.ReadFile(dst) //nolint:gosec // G304: t.TempDir() 配下のテスト用ファイル
	if err != nil {
		t.Fatalf("read existing file: %v", err)
	}
	if string(got) != sentinel {
		t.Errorf("existing file was modified: %q", got)
	}
}

// TestPrepareBackupDestCreatesPrivateEmptyFile は、出力先が作成時点から 0600 で
// あり、中身が空(VACUUM INTO が受け入れる空の DB プレースホルダ)であることを
// 確認する。緩い親ディレクトリに置いても、作成→chmod の窓で暗号文が他ユーザーへ
// 露出しないための不変条件である。
func TestPrepareBackupDestCreatesPrivateEmptyFile(t *testing.T) {
	// 緩い親(--out に共有ディレクトリを指定された状況を模す)。
	parent := filepath.Join(t.TempDir(), "shared")
	//nolint:gosec // G301: 緩い親ディレクトリを意図的に作り、それでもファイルが 0600 で作られることを検証する
	if err := os.MkdirAll(parent, 0o777); err != nil {
		t.Fatalf("make loose parent: %v", err)
	}
	dst := filepath.Join(parent, "snap.db")

	if err := prepareBackupDest(dst); err != nil {
		t.Fatalf("prepareBackupDest: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat created file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != dbFileMode {
		t.Errorf("created file perm = %04o, want %04o", perm, dbFileMode)
	}
	if info.Size() != 0 {
		t.Errorf("created file size = %d, want 0 (empty db placeholder)", info.Size())
	}
}

// TestPrepareBackupDestRefusesExisting は、既存ファイルには O_EXCL で触れず
// エラーにすることを確認する(cmdBackup 経由の上書き拒否を prepareBackupDest
// 単体でも保証する)。
func TestPrepareBackupDestRefusesExisting(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "exists.db")
	if err := os.WriteFile(dst, []byte("keep"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := prepareBackupDest(dst)
	if err == nil {
		t.Fatal("prepareBackupDest overwrote an existing file, want an error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v, want it to mention the file already exists", err)
	}
	got, err := os.ReadFile(dst) //nolint:gosec // G304: t.TempDir() 配下のテスト用ファイル
	if err != nil {
		t.Fatalf("read existing: %v", err)
	}
	if string(got) != "keep" {
		t.Errorf("existing file was modified: %q", got)
	}
}

// TestBackupRequiresOut は、--out が必須であることを確認する。
func TestBackupRequiresOut(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	newTestStoreAt(t, src)

	_, _, err := runBackup(t, "--db", src)
	if err == nil {
		t.Fatal("cmdBackup without --out succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "--out is required") {
		t.Errorf("error = %v, want it to say --out is required", err)
	}
}

// TestBackupRejectsMissingDatabase は、存在しない DB に対してエラーになり、
// 出力先を作らないことを確認する。
func TestBackupRejectsMissingDatabase(t *testing.T) {
	src := filepath.Join(t.TempDir(), "does-not-exist.db")
	dst := filepath.Join(t.TempDir(), "hokora.bak.db")

	_, _, err := runBackup(t, "--db", src, "--out", dst)
	if err == nil {
		t.Fatal("cmdBackup on a missing database succeeded, want an error")
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("backup output was created despite the error (err=%v)", statErr)
	}
}

// TestVerifyBackupRejectsCorruptFile は、SQLite として開けない出力を
// verifyBackup が弾くことを確認する(切り詰め・破損の検出)。
func TestVerifyBackupRejectsCorruptFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(bad, []byte("this is not a sqlite database"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if err := verifyBackup(t.Context(), bad); err == nil {
		t.Error("verifyBackup accepted a corrupt file, want an error")
	}
}

// TestVerifyBackupRejectsWrongSchemaVersion は、スキーマ版が本バイナリと
// 異なるバックアップを verifyBackup が弾くことを確認する。
func TestVerifyBackupRejectsWrongSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otherver.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// スキーマ版だけを本バイナリと違う値にした、開ける DB を作る。
	if _, err := db.ExecContext(t.Context(), "PRAGMA user_version = 999"); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	err = verifyBackup(t.Context(), path)
	if err == nil {
		t.Fatal("verifyBackup accepted a wrong schema version, want an error")
	}
	if !strings.Contains(err.Error(), "schema version") {
		t.Errorf("error = %v, want it to mention the schema version", err)
	}
}

// newUnsealedVaultAt は既知パスに keyring 付きの DB を作り、unseal 済みの Vault と
// その MK を返す(newTestVault と同じ手順を、バックアップ元にできるよう指定パスで
// 組む)。argon2 は keyring 作成と unseal で 2 回走る。
func newUnsealedVaultAt(t *testing.T, path string) (*Vault, *Store, []byte) {
	t.Helper()

	store := newTestStoreAt(t, path)
	mk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, dek, err := NewKeyring(mk, vaultNow)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	Zero(dek)
	if err := InsertKeyring(t.Context(), store.DB(), kr); err != nil {
		t.Fatalf("InsertKeyring: %v", err)
	}
	v := NewVault(store.DB(), discardLogger(), 16)
	unsealForTest(t, v, mk)
	return v, store, mk
}

// TestBackupPreservesEncryptedSecretsEndToEnd は backup の中核の約束を確かめる:
// 稼働中(unsealed)の DB から取ったスナップショットが、(1) 暗号文をバイト単位で
// そのまま含み、(2) 元と同じ MK でそのまま復号でき、(3) バックアップ後に書いた
// secret は含まない(取得時点の point-in-time である)こと。
//
// captureOutput を使うため t.Parallel() は呼ばない(main_test.go 参照)。
func TestBackupPreservesEncryptedSecretsEndToEnd(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	v, store, mk := newUnsealedVaultAt(t, src)

	projectID := insertProject(t, store.DB(), testProjectSlug, false)
	envID := insertEnvironment(t, store.DB(), projectID, testEnvSlug, false)
	env := &EnvironmentRef{
		ProjectSlug: testProjectSlug, EnvSlug: testEnvSlug,
		ProjectID: projectID, EnvironmentID: envID,
	}
	ac := secretAudit()

	const plaintext = "postgres://user:pw@db/prod" //nolint:gosec // G101: テスト用のダミー secret 値(実在の認証情報ではない)
	if err := PutSecret(t.Context(), v, env, "DATABASE_URL", []byte(plaintext), ac); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	// 取得時点のスナップショットを取る。
	dst := filepath.Join(t.TempDir(), "backup", "hokora.bak.db")
	if _, _, err := runBackup(t, "--db", src, "--out", dst); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	// **バックアップ後**に書いた secret は、取得済みスナップショットに現れない。
	if err := PutSecret(t.Context(), v, env, "ADDED_AFTER_BACKUP", []byte("late"), ac); err != nil {
		t.Fatalf("PutSecret after backup: %v", err)
	}

	// (1) 暗号文がバイト単位で忠実にコピーされている。
	wantEnc, wantNonce := readVersionBytes(t, store, 1)
	backup := openReadOnly(t, dst)
	var gotEnc, gotNonce []byte
	if err := backup.QueryRowContext(t.Context(),
		`SELECT v.value_enc, v.nonce FROM item_versions v
		 JOIN items i ON i.id = v.item_id
		 WHERE i.key = 'DATABASE_URL' AND v.version = 1`).Scan(&gotEnc, &gotNonce); err != nil {
		t.Fatalf("read ciphertext from backup: %v", err)
	}
	if !bytes.Equal(gotEnc, wantEnc) || !bytes.Equal(gotNonce, wantNonce) {
		t.Error("backup ciphertext/nonce differ from the source")
	}

	// (3) point-in-time: 後から書いた key はバックアップに無い。
	var late int
	if err := backup.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM items WHERE key = 'ADDED_AFTER_BACKUP'`).Scan(&late); err != nil {
		t.Fatalf("count late key in backup: %v", err)
	}
	if late != 0 {
		t.Errorf("backup contains %d rows for a key written after the backup, want 0", late)
	}

	// (2) バックアップを開き直し、同じ MK で unseal して復号できる。
	// backup を書き込み可能で開くのは、RevealSecret が監査ログを 1 行足す
	// (fail closed。ルール 22)ため。復号できること自体がここでの主眼。
	restored, err := OpenStore(t.Context(), dst)
	if err != nil {
		t.Fatalf("OpenStore(backup): %v", err)
	}
	defer restored.Close()

	// スラッグから引き直す(ID 直接参照に頼らず、行が丸ごと往復したことを見る)。
	restoredEnv, err := ResolveEnvironment(t.Context(), restored.DB(), testProjectSlug, testEnvSlug)
	if err != nil {
		t.Fatalf("ResolveEnvironment(backup): %v", err)
	}
	rv := NewVault(restored.DB(), discardLogger(), 16)
	unsealForTest(t, rv, mk)
	got, err := RevealSecret(t.Context(), rv, restoredEnv, "DATABASE_URL", 0, ac)
	if err != nil {
		t.Fatalf("RevealSecret(backup): %v", err)
	}
	if got != plaintext {
		t.Errorf("decrypted from backup = %q, want %q", got, plaintext)
	}
}

// TestBackupRoundTripsAllTables は project / environment / item / item_versions /
// audit_logs の行数がバックアップで一致することを確認する(VACUUM INTO が
// 特定のテーブルだけ取りこぼさないこと)。
//
// captureOutput を使うため t.Parallel() は呼ばない。
func TestBackupRoundTripsAllTables(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	store := newTestStoreAt(t, src)
	db := store.DB()

	projectID := insertProject(t, db, "web", false)
	envID := insertEnvironment(t, db, projectID, "prod", false)
	itemID := insertItemRow(t, db, envID, "DATABASE_URL", false)
	insertItemVersionRow(t, db, itemID, 1, "user:1")
	if err := RecordAudit(t.Context(), db,
		auditCtx{Actor: ActorAnonymous, Now: vaultNow}.entry(ActionSeal, ResultSuccess, nil)); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "hokora.bak.db")
	if _, _, err := runBackup(t, "--db", src, "--out", dst); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	backup := openReadOnly(t, dst)
	for _, table := range []string{"projects", "environments", "items", "item_versions", "audit_logs"} {
		var want, got int
		//nolint:gosec // G202: table はテスト内のリテラルのみ
		if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&want); err != nil {
			t.Fatalf("count %s in source: %v", table, err)
		}
		//nolint:gosec // G202: table はテスト内のリテラルのみ
		if err := backup.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
			t.Fatalf("count %s in backup: %v", table, err)
		}
		if got != want {
			t.Errorf("%s: backup has %d rows, source has %d", table, got, want)
		}
	}
}

// TestOpenStoreReadOnly は、読み取り専用ハンドルが (1) 存在しないパスを拒否し、
// (2) 読めるが書けない handle を返し、(3) 対象の隣に -wal / -shm / -journal の
// 随伴ファイルを作らないことを確認する。verifyBackup がスナップショットを副作用
// なく点検できる前提そのものである。
//
// captureOutput を使う runBackup を呼ぶため t.Parallel() は呼ばない。
func TestOpenStoreReadOnly(t *testing.T) {
	t.Run("rejects a nonexistent path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.db")
		store, err := OpenStoreReadOnly(t.Context(), missing)
		if err == nil {
			store.Close()
			t.Fatal("OpenStoreReadOnly opened a nonexistent path, want an error")
		}
	})

	t.Run("read only, usable, no sidecars", func(t *testing.T) {
		// 随伴ファイルの無い単一ファイル DB を作るため、VACUUM INTO を通す。
		src := filepath.Join(t.TempDir(), "hokora.db")
		srcStore := newTestStoreAt(t, src)
		insertProject(t, srcStore.DB(), "web", false)

		snap := filepath.Join(t.TempDir(), "snap.db")
		if _, _, err := runBackup(t, "--db", src, "--out", snap); err != nil {
			t.Fatalf("cmdBackup: %v", err)
		}

		store, err := OpenStoreReadOnly(t.Context(), snap)
		if err != nil {
			t.Fatalf("OpenStoreReadOnly: %v", err)
		}
		defer store.Close()

		// 読めること。
		var slug string
		if err := store.DB().QueryRowContext(t.Context(),
			`SELECT slug FROM projects WHERE slug = 'web'`).Scan(&slug); err != nil {
			t.Fatalf("read from read-only store: %v", err)
		}
		if slug != "web" {
			t.Errorf("slug = %q, want web", slug)
		}

		// 書けないこと(mode=ro)。
		if _, err := store.DB().ExecContext(t.Context(),
			`INSERT INTO projects (slug, name, created_at, updated_at) VALUES ('x', 'x', 0, 0)`); err == nil {
			t.Error("a write through the read-only handle succeeded, want a read-only error")
		}

		// 随伴ファイルを作っていないこと(WAL の pragma を付けないため)。
		for _, sidecar := range []string{snap + "-wal", snap + "-shm", snap + "-journal"} {
			if _, err := os.Stat(sidecar); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("unexpected sidecar %s (err=%v)", sidecar, err)
			}
		}
	})
}

// TestRemoveBackupArtifact は、失敗時の後片付けが存在しないファイルを許容し
// (ErrNotExist を成功扱い)、存在するファイルは消すことを確認する。
// VACUUM 失敗直後に「そもそも作られなかった」場合でもエラーを合流させないため。
func TestRemoveBackupArtifact(t *testing.T) {
	t.Parallel()

	t.Run("tolerates a missing file", func(t *testing.T) {
		t.Parallel()
		if err := removeBackupArtifact(filepath.Join(t.TempDir(), "never-created.db")); err != nil {
			t.Errorf("removeBackupArtifact on a missing path = %v, want nil", err)
		}
	})

	t.Run("removes an existing file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "half-written.db")
		if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		if err := removeBackupArtifact(path); err != nil {
			t.Errorf("removeBackupArtifact = %v, want nil", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("file still exists after removeBackupArtifact (err=%v)", err)
		}
	})
}

// TestRunDispatchesBackup は run が "backup" を cmdBackup へ振り分け、その引数
// (--db / --out)が正しく渡ることを、実際にファイルが書かれることで確認する。
// あわせて未知フラグが parseFlags 経由でエラーになること(振り分けの取りこぼしで
// 黙って成功しない)を固定する。
//
// captureOutput を使うため t.Parallel() は呼ばない。
func TestRunDispatchesBackup(t *testing.T) {
	src := filepath.Join(t.TempDir(), "hokora.db")
	newTestStoreAt(t, src)
	dst := filepath.Join(t.TempDir(), "hokora.bak.db")

	var err error
	captureOutput(t, func() {
		err = run(t.Context(), []string{"backup", "--db", src, "--out", dst})
	})
	if err != nil {
		t.Fatalf("run([backup ...]) = %v, want nil", err)
	}
	if _, statErr := os.Stat(dst); statErr != nil {
		t.Fatalf("backup was not created through run(): %v", statErr)
	}

	var flagErr error
	captureOutput(t, func() {
		flagErr = run(t.Context(), []string{"backup", "--bogus"})
	})
	if flagErr == nil {
		t.Fatal("run([backup --bogus]) = nil, want a flag error")
	}
}
