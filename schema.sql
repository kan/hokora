-- hokora schema (DESIGN §5.2)
--
-- 方針:
--   - 外部キーは全て ON DELETE RESTRICT。CASCADE を使わない
--   - audit_logs は FK を持たない(参照先が論理削除されても記録は残る)
--   - project / environment / item は deleted_at による論理削除
--   - user / machine は disabled(deleted_at を持たない)
--   - grant / session のみ物理 DELETE を許可
--   - 論理削除された slug / key は再利用できる(部分 UNIQUE インデックス)
--   - 時刻は全て Unix 秒(INTEGER)

CREATE TABLE keyring (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    dek_wrapped     BLOB NOT NULL,
    dek_nonce       BLOB NOT NULL,
    kdf_salt        BLOB NOT NULL,
    dek_version     INTEGER NOT NULL DEFAULT 1 CHECK (dek_version > 0 AND dek_version <= 4294967295),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- ロールは admin のみ。削除は disabled
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,      -- argon2id、PHC 文字列形式(DESIGN §7.2)
    must_change_pw  INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- token は SHA-256 ハッシュ。CSRF は保存しない(セッショントークンから導出)
-- session は物理 DELETE を許可(削除モデルの例外)
CREATE TABLE sessions (
    token_hash      BLOB PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,   -- 絶対期限
    last_seen_at    INTEGER NOT NULL,   -- idle 期限の判定用
    remote_addr     TEXT
);

CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- client_secret は高エントロピーなので SHA-256(DESIGN §7.1)
-- 削除は disabled
CREATE TABLE machines (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id       TEXT NOT NULL UNIQUE,
    secret_hash     BLOB NOT NULL,      -- SHA-256(client_secret)
    name            TEXT NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    last_auth_at    INTEGER
);

CREATE TABLE projects (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    deleted_at      INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- 論理削除された slug は再利用可能(THREAT_MODEL §11.2)
CREATE UNIQUE INDEX idx_projects_slug ON projects(slug) WHERE deleted_at IS NULL;

CREATE TABLE environments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    deleted_at      INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE UNIQUE INDEX idx_environments_slug
    ON environments(project_id, slug) WHERE deleted_at IS NULL;

-- grant は物理 DELETE を許可(削除モデルの例外)
CREATE TABLE machine_grants (
    machine_id      INTEGER NOT NULL REFERENCES machines(id) ON DELETE RESTRICT,
    environment_id  INTEGER NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (machine_id, environment_id)
);

CREATE TABLE items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    environment_id  INTEGER NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    key             TEXT NOT NULL,
    current_version INTEGER NOT NULL DEFAULT 0 CHECK (current_version >= 0 AND current_version <= 4294967295),
    deleted_at      INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE UNIQUE INDEX idx_items_key
    ON items(environment_id, key) WHERE deleted_at IS NULL;

-- 追記専用。コメント欄は持たない
-- version / dek_version の CHECK は itemAAD の uint32 変換の安全性を保証する
CREATE TABLE item_versions (
    item_id         INTEGER NOT NULL REFERENCES items(id) ON DELETE RESTRICT,
    version         INTEGER NOT NULL CHECK (version > 0 AND version <= 4294967295),
    value_enc       BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    dek_version     INTEGER NOT NULL CHECK (dek_version > 0 AND dek_version <= 4294967295),
    created_at      INTEGER NOT NULL,
    created_by      TEXT NOT NULL,
    PRIMARY KEY (item_id, version)
);

-- 監査ログ。追記専用
-- slug / key は再利用可能なので、表示用の target に加えて immutable ID を持つ
-- (THREAT_MODEL §10.2)
CREATE TABLE audit_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              INTEGER NOT NULL,
    actor           TEXT NOT NULL,      -- 'user:1' | 'machine:3' | 'anonymous'
    actor_user_id   INTEGER,
    actor_machine_id INTEGER,
    action          TEXT NOT NULL,      -- audit.go の allowlist
    target          TEXT,               -- 表示用 'myapp/prod/DATABASE_URL'
    target_project_id     INTEGER,
    target_environment_id INTEGER,
    target_item_id        INTEGER,
    target_user_id        INTEGER,
    target_machine_id     INTEGER,
    result          TEXT NOT NULL,      -- 'success' | 'failure'
    remote_addr     TEXT,
    detail          TEXT                -- 型付き JSON のみ(DESIGN §5.4)
);

CREATE INDEX idx_audit_at ON audit_logs(at DESC);
CREATE INDEX idx_audit_actor_user ON audit_logs(actor_user_id, at DESC);
CREATE INDEX idx_audit_actor_machine ON audit_logs(actor_machine_id, at DESC);
CREATE INDEX idx_audit_target_item ON audit_logs(target_item_id, at DESC);
