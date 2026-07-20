# hokora 設計文書

前提となる脅威モデルは `docs/THREAT_MODEL.md` を参照。

---

## 1. 概要

hokora は、単一組織向けのミニマルな秘匿情報管理サーバーである。

- **サーバー**: Go による単一バイナリ。SQLite 埋め込み。外部依存なし
- **クライアント**: Go SDK(第一級)と CLI(移行用)
- **Web UI**: html/template による最小限の管理画面
- **通信**: HTTPS(Let's Encrypt DNS-01、証明書取得は外部ホスト)
- **データモデル**: project / env / item(組織は単一)

名前は祠(hokora)に由来する。語源は「神庫(hokura)」= 神の倉。

---

## 2. 設計原則

### P1. 単一バイナリ、外部依存ゼロ

### P2. 機能を足さない。むしろ削る

以下は **明示的に実装しない**:

- マルチテナント / 複数組織
- Secret の自動ローテーション
- 外部サービス連携 / PKI / SSH キー管理 / Dynamic secrets / Honey tokens
- SSO / OIDC / SPA フロントエンド
- **`.env` エクスポート**(`> .env` でディスクに書かれる)
- **item のコメント/メモ欄**(自由記述欄には必ず秘密が書かれる)
- **viewer ロール**(admin 単一)
- **TLS 証明書の自動取得**(certbot に任せる)
- **物理削除**(grant / session を除く)
- **IP allowlist 機能**(firewalld の責務)
- **レスポンス圧縮**(§9.5)

### P3. 暗号を自作しない

### P4. 監査可能性を最初から

**ただし fail closed は「セキュリティを下げる操作」のみ**
(THREAT_MODEL §10.4)。緊急遮断操作を監査障害で止めてはならない。

### P5. 依存を最小に

### P6. 秘密を持たない、状態を持たない

- MK: ディスクに置かない
- DNS-01 API 認証情報: **hokora サーバーに置かない**(certbot は別ホスト)
- CSRF トークン: **DB に保存しない**(セッショントークンから導出)

**保存しないものは、保存方法の問題も漏洩リスクも持たない。**

### P7. 過大な主張をしない

防御の記述は、実際の仕組みの挙動を確認してから書く。
godoc / README / 文書のいずれにおいても、守れないものを守れると書かない。

---

## 3. 技術選択とその根拠

### 3.1 なぜ SQLite か

- 単一ファイル。外部プロセス不要
- この規模(secret 数百、リクエスト数十/日)では性能上の問題が皆無
- **MySQL 対応はしない**(分離の観点)

**ドライバ**: `modernc.org/sqlite`(CGO 不要、純 Go)

#### PRAGMA の適用方法(設計要件)

**SQLite の PRAGMA は接続単位である。`database/sql` は複数の物理接続を開き、
障害時には接続を再生成する。起動時に 1 接続で `PRAGMA foreign_keys = ON` を
実行しても、他の接続では無効のままになる。**

`foreign_keys` はデフォルト OFF であり、これが効いていなければ
`ON DELETE RESTRICT` による保護(THREAT_MODEL §11)は成立しない。

**主方式: DSN の `_pragma=` で全接続に適用する。**

```go
dsn := "file:" + path + "?" +
    "_pragma=journal_mode(WAL)" +
    "&_pragma=foreign_keys(ON)" +
    "&_pragma=busy_timeout(5000)" +
    "&_pragma=synchronous(FULL)"
db, err := sql.Open("sqlite", dsn)
```

`modernc.org/sqlite` は DSN の `_pragma=` を **各物理接続の確立時に実行する**。

**代替方式(DSN 方式がテストで検証できなかった場合):**

`modernc.org/sqlite` の接続後 hook(`sqlite.RegisterConnectionHook` 等)を用いて、
**各接続の確立時に PRAGMA を適用する**。

**`db.SetMaxOpenConns(1)` は単独では不十分である。**
1 接続にしても、その接続に PRAGMA を適用しなければ意味がない。また、
接続が障害等で再生成される可能性もある。採用する場合は
「単一接続を確立 → PRAGMA 適用 → その接続を維持する」まで規定すること。

**M1 の完了条件:**

- 複数の `*sql.Conn` を同時に取得し、**それぞれで `PRAGMA foreign_keys` が 1 を
  返すことをテストで確認する**
- 接続を意図的に閉じて再取得し、**再生成された接続でも 1 を返すこと**
- 意図的に FK 違反を起こし、RESTRICT でエラーになることをテスト
- `PRAGMA foreign_key_check` が空を返すことをテスト

#### migrate の方式

**`PRAGMA user_version` を使う。** MVP は単一スキーマなので、
`schema_version` テーブルを作るまでもない。

### 3.2 なぜ Redis を使わないか

| 用途 | hokora での実装 |
|------|----------------|
| セッションストア | SQLite テーブル |
| レート制限 | プロセス内 map + mutex(上限つき) |
| キャッシュ | 不要 |
| 短命トークン | プロセス内 map + mutex(上限つき) |

### 3.3 なぜ html/template か

- ビルドパイプラインが増えない
- CSRF がフォーム前提で素直
- **秘匿情報を扱う画面が npm 依存ツリーを持たない**

### 3.4 なぜ手動 unseal か / 3.5 なぜ Envelope Encryption か

THREAT_MODEL §5.3、§8.1 を参照。

### 3.6 なぜ certbot を別ホストで動かすか

Let's Encrypt の DNS-01 チャレンジには DNS プロバイダの API 認証情報が必要。

- hokora に組み込む → hokora が秘密を持つ(P6 違反)
- hokora ホストで certbot → **認証情報が hokora のディスクに置かれる。
  T3 でディスクが漏れたら DNS を乗っ取られる**
- **別ホスト(Ansible 管理ホスト)で certbot** ← **採用**

**hokora 側の要件:**
- `--tls-cert` / `--tls-key` でファイルパスを指定
- **SIGHUP で証明書をリロード**
- **リロードに失敗したら、古い有効な証明書を維持する**
- **証明書と秘密鍵はペアとして原子的に切り替える**(§3.7)

### 3.7 証明書ペアの原子的な切り替え

**証明書と秘密鍵は 2 ファイルである。各ファイルを個別に `rename` しても、
ペアとしては原子的でない。** 片方だけが新しい状態で SIGHUP を受けると、
証明書と鍵が一致せずリロードに失敗する。

**採用する方式: versioned directory + symlink 切り替え。**

```
/var/lib/hokora/tls/
├── 20260717-120000/
│   ├── cert.pem
│   └── key.pem
├── 20260915-120000/
│   ├── cert.pem
│   └── key.pem
└── current -> 20260915-120000    ← symlink の付け替えは原子的
```

- hokora は `--tls-dir /var/lib/hokora/tls/current` を見る
- certbot の deploy hook が新しいディレクトリを作り、`current` symlink を
  `rename` で切り替えてから SIGHUP を送る
- **リロードに失敗したら、hokora は古い証明書を保持したまま動き続ける**

### 3.8 なぜ公的 CA か(CT ログのトレードオフ)

THREAT_MODEL §5.2 を参照。

---

## 4. アーキテクチャ

### 4.1 プロセス構成

```
hokora serve  (実行ユーザー: hokora、非 root、mlockall 済み)
  │
  ├─ Machine API listener
  │    bind: 0.0.0.0:9443
  │    mux:  machineMux  ← 独立した ServeMux
  │    ├─ POST /v1/auth/token
  │    ├─ GET  /v1/secrets
  │    ├─ GET  /v1/secrets/{key}
  │    └─ GET  /healthz     (バージョンは返さない)
  │    ※ firewalld でアプリサーバー IP のみ allow(THREAT_MODEL B3)
  │
  ├─ Web UI listener
  │    bind: <VPN IF の IP>:8443  (デフォルト 127.0.0.1)
  │    mux:  uiMux  ← 独立した ServeMux
  │    └─ /ui/*
  │
  ├─ Admin socket
  │    unix:///run/hokora/admin.sock (0600 hokora:hokora)
  │    mux:  adminMux  ← 独立した ServeMux
  │    └─ /unseal /seal /status /rotate-master
  │
  └─ メモリ上の状態(mlockall により swap されない)
       ├─ sealed / unsealed
       ├─ DEK(unsealed 時のみ。MK/KEK は保持しない)
       ├─ machine token: map[[32]byte]tokenInfo(上限つき)
       └─ レート制限カウンタ: map[key]*bucket(上限つき、TTL つき)
```

**mux の分離が必須である理由:**

2 つの `http.Server` を別ポートで起動しても、**両方に同じ `ServeMux` を渡せば、
`:9443/ui/...` と `:8443/v1/...` の両方が応答してしまう。**

**M4 の完了条件:**
- Machine API listener で `/ui/login` が **404**
- Web UI listener で `/v1/auth/token` が **404**
- Web UI listener で `/healthz` が **404**

**bind address:**
- Web UI の bind address は設定必須。**デフォルトは `127.0.0.1:8443`**
- `0.0.0.0` を指定した場合、起動時に警告ログを出す
- Machine API はデフォルト `0.0.0.0:9443`(到達制限は firewalld の責務)

### 4.2 実行ユーザーと mlockall

**hokora は専用ユーザー `hokora` で実行する。root で実行してはならない。**

**起動時に `mlockall(MCL_CURRENT|MCL_FUTURE)` を実行する**(THREAT_MODEL §5.3)。

```go
// serve の最初期に実行する
if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
    // LimitMEMLOCK が不足している可能性が高い
    return fmt.Errorf("mlockall failed (LimitMEMLOCK=infinity is required): %w", err)
}
```

- **失敗したら起動を中止する。** T3 の防御が成立しないため
- systemd unit に **`LimitMEMLOCK=infinity` が必須**
- これにより hokora のメモリ(数十 MB)は swap に出ない
- システム全体の swap は無効化しない(VPS のメモリ制約を考慮)

**依存:** `golang.org/x/sys/unix` を追加する。
(`syscall.Syscall(syscall.SYS_MLOCKALL, ...)` で直接呼べば依存は増えないが、
可読性と移植性のため `x/sys` を使う。これは P5 の例外として承認する)

### 4.3 systemd ハードニング(必須)

```ini
[Service]
User=hokora
Group=hokora
ExecStart=/usr/local/bin/hokora serve

# THREAT_MODEL §5.3: メモリ内容をディスクに残さない
LimitCORE=0
LimitMEMLOCK=infinity     # mlockall に必須

# ハードニング
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
PrivateMounts=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
RemoveIPC=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

ReadWritePaths=/var/lib/hokora
RuntimeDirectory=hokora
RuntimeDirectoryMode=0700
```

**ホストレベルで必須**(THREAT_MODEL §5.3):
- systemd-coredump の無効化
- **kdump の無効化**
- firewalld による Machine API の IP allowlist

**アプリケーションサーバー側の unit にも `PrivateMounts=true` を推奨**
(THREAT_MODEL B7。他サービスの credential directory を不可視にする)。

### 4.4 状態機械と並行制御

```go
type Vault struct {
    mu     sync.RWMutex
    state  State
    dek    []byte  // unsealed 時のみ非 nil
    tokens *tokenStore
}
```

**要求される性質:**

| # | 性質 |
|---|------|
| C1 | secret の暗号/復号操作は、開始から完了まで read lock を保持する |
| C2 | `Seal()` は write lock を取得する。進行中の暗号操作の完了を待つ |
| C3 | `Seal()` 完了後、DEK を参照している goroutine が存在しない |
| C4 | `Unseal()` は鍵をローカル変数で検証し、完全に成功してから一度に公開する |
| C5 | `Seal()` 時に machine token store を空にする |
| C6 | **トークンの発行処理全体(unsealed 確認 → credential 検証 → store への追加)が read lock 内で完結する** |
| C7 | **ロックの取得順序を固定する: Vault.mu → tokenStore.mu。逆順で取得しない** |
| **C8** | **`machine.rotate_secret` / `machine.disable` の「DB 更新 → トークン削除」を Vault の write lock 内で実行する** |
| **C9** | **ログイン処理は、セッション INSERT と同一トランザクション内で `password_hash` を再読し、検証に使った値と一致することを確認する。不一致なら失敗させる** |
| **C10** | **`rotate-master` 全体を専用 mutex で直列化する** |

#### C6 が必要な理由(トークン発行 vs seal)

```
auth goroutine:  unsealed を確認
seal goroutine:               write lock 取得、token store を clear、sealed へ
auth goroutine:  新しい token を store に追加   ← seal をすり抜けた
```

#### C8 が必要な理由(トークン発行 vs credential 再発行)

**C6 と同型の競合が、revoke 系にも存在する。**

```
auth goroutine:   旧 client_secret で検証成功
rotate goroutine: secret_hash 更新 + 監査を tx で commit
rotate goroutine: tokenStore.DeleteByMachine(id)   ← 削除実行
auth goroutine:   トークンを store に追加          ← 削除をすり抜けた
```

**旧 credential で作られたトークンが、`rotate_secret` 完了後に最大 15 分
生き残る。** §4.5 の再検査は `disabled` と grant しか見ないため、
`rotate_secret` ではトークン削除が唯一の遮断手段であり、すり抜けは
R4 / R13 の緩和策そのものを破る。

**`rotate_secret` は「漏洩したから回す」操作である。** まさに攻撃者が
旧 credential を持っている状況で発生する。

**修正:** 「DB tx commit → トークン削除」を Vault の **write lock 内**で実行する。
C6 により発行は read lock 内で完結しているので、write lock は進行中の発行の
完了を待ち、発行済みトークンは必ず削除対象に含まれる。C7 とも整合する。

write lock の保持は tx + map 削除の数 ms であり、argon2 を含まないため許容範囲。

#### C9 が必要な理由(ログイン vs パスワード変更)

**同型の競合。argon2 の所要時間(数百 ms)ぶん、競合ウィンドウが machine 側より
現実的に広い。**

```
login goroutine:  旧 password_hash を読み、argon2 検証(数百 ms)
change goroutine: hash 更新 + 全 session DELETE + 監査を tx で commit
login goroutine:  新 session を INSERT           ← 削除をすり抜けた
```

**修正:** ログイン処理を以下の構造にする。

```
1. password_hash を読む(tx 外)
2. argon2 で検証(tx 外。数百 ms)
3. トランザクション開始
4. password_hash を再読し、手順 1 で読んだ値と一致するか確認
   → 不一致なら失敗(その間にパスワードが変更された)
5. session を INSERT
6. commit
```

`password_change` 側は「hash 更新 + sessions DELETE + 監査」が既に 1 tx なので、
SQLite の直列化により決着する。**ロックを増やさずに済む。**

#### C10 が必要な理由(rotate-master の同時実行)

```
rotate A: 旧 keyring を読み、旧 MK で検証
rotate B: 旧 keyring を読み、旧 MK で検証
rotate A: 新 MK-A で commit
rotate B: 新 MK-B で commit    ← 最後に commit した方だけが有効
```

両方の新 MK が 1Password にあればデータ喪失にはならないが、
**「どの MK が有効か」という運用認識が壊れる。**

**修正:** `rotate-master` 全体を専用 mutex で直列化する。

#### テスト

**`go test -race` では C1〜C3、C6、C8、C9 の違反を検出できない。**
以下を明示的にテストする:

- unseal → トークン発行 → seal → unseal → **旧トークンが無効であること**
- **トークン発行と seal を並行実行し、seal 後に有効なトークンが存在しないこと**
- **`rotate_secret` と旧 credential による認証を並行実行し、rotate 完了後に
  旧 credential 由来の有効トークンが存在しないこと**(C8)
- **`password_change` と旧パスワードによるログインを並行実行し、変更後に
  旧パスワード由来の有効セッションが存在しないこと**(C9)
- **`rotate-master` を並行実行し、直列化されること**(C10)
- 復号中に seal を呼び、復号が完了してから seal されること
- seal 後に DEK がゼロクリアされていること

### 4.5 認可の再検査

**トークンは「認証の証明」であり、「認可の証明」ではない。**

各リクエスト時に再検査する:

- machine が disabled になっていないか
- 対象 environment への grant が残っているか
- **environment / project が論理削除されていないか**(THREAT_MODEL §11.1)
- **トークンの有効期限**(§7.1)

Web UI のセッションでも各リクエストで:

- ユーザーの `disabled`
- **セッションの絶対期限(12 時間)と idle 期限(2 時間)**

**期限判定を sweep に依存してはならない。** sweep はメモリ / DB の掃除であって、
認証上の期限判定ではない。sweep が 1 分ごとなら、最大 1 分余分に使えてしまう。

---

## 5. データモデル

### 5.1 削除モデル

THREAT_MODEL §11 を参照。

### 5.2 スキーマ

```sql
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
    password_hash   TEXT NOT NULL,      -- argon2id、PHC 文字列形式(§7.2)
    must_change_pw  INTEGER NOT NULL DEFAULT 0,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- token は SHA-256 ハッシュ。CSRF は保存しない(§7.3 で導出)
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

-- client_secret は高エントロピーなので SHA-256(§7.1)
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

-- grant は物理 DELETE を許可(削除モデルの例外)
CREATE TABLE machine_grants (
    machine_id      INTEGER NOT NULL REFERENCES machines(id) ON DELETE RESTRICT,
    environment_id  INTEGER NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (machine_id, environment_id)
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
-- immutable ID を持つ(THREAT_MODEL §10.2)
CREATE TABLE audit_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              INTEGER NOT NULL,
    actor           TEXT NOT NULL,      -- 'user:1' | 'machine:3' | 'anonymous'
    actor_user_id   INTEGER,            -- immutable ID
    actor_machine_id INTEGER,           -- immutable ID
    action          TEXT NOT NULL,      -- §5.4 の allowlist
    target          TEXT,               -- 表示用 'myapp/prod/DATABASE_URL'
    target_project_id     INTEGER,      -- immutable ID
    target_environment_id INTEGER,      -- immutable ID
    target_item_id        INTEGER,      -- immutable ID
    target_user_id        INTEGER,      -- immutable ID
    target_machine_id     INTEGER,      -- immutable ID
    result          TEXT NOT NULL,      -- 'success' | 'failure'
    remote_addr     TEXT,
    detail          TEXT                -- §5.4 の型付き JSON のみ
);

CREATE INDEX idx_audit_at ON audit_logs(at DESC);
CREATE INDEX idx_audit_actor_user ON audit_logs(actor_user_id, at DESC);
CREATE INDEX idx_audit_actor_machine ON audit_logs(actor_machine_id, at DESC);
CREATE INDEX idx_audit_target_item ON audit_logs(target_item_id, at DESC);
```

**監査ログに immutable ID を持つ理由:**

slug / key は再利用可能(THREAT_MODEL §11.2)なので、`target` 文字列だけでは
数年後に「旧 item か再作成後の item か」を判別できない。ID を併記することで、
`target` は人間が読むための表示用、ID は機械が追跡するための正確な識別子、
という役割分担になる。

**外部キーの方針:**

- **すべて `ON DELETE RESTRICT`。** CASCADE を使わない
- **`audit_logs` は FK を持たない**(参照先が論理削除されても記録は残るべきであり、
  また監査ログの INSERT が FK 検査で失敗するのは避けたい)

### 5.3 secret 値の型

| 側 | 型 |
|----|-----|
| DB | `BLOB` |
| JSON API | `string` |
| `hokora run` | 環境変数 |
| SDK | `[]byte` |

**制約:**

- **有効な UTF-8 であること**(JSON にエンコードするため)
- **NUL バイト(0x00)を含まないこと**(環境変数として展開するため)
- **最大 64 KB**

これらは書き込み時にサーバー側で検証する。違反は 400 を返す。

### 5.4 監査ログの `action` と `detail`

**`action` は以下の allowlist のみ:**

```
secret.read        secret.write       secret.delete      secret.reveal
unseal.attempt     seal               master.rotate
auth.machine       auth.user          logout
user.create        user.disable       user.password_change
machine.create     machine.disable    machine.rotate_secret
grant.create       grant.delete
project.create     project.delete
environment.create environment.delete
```

**`detail` は型付き構造体を marshal したもののみ。**

```go
type AuditDetail struct {
    Version        *int    `json:"version,omitempty"`
    Reason         *string `json:"reason,omitempty"`  // 下記の定数のみ
    Via            *string `json:"via,omitempty"`     // "socket" | "web"
    Count          *int    `json:"count,omitempty"`
    SubjectDigest  *string `json:"subject_digest,omitempty"`  // §5.5
}

const (
    ReasonInvalidCredentials = "invalid_credentials"
    ReasonRateLimited        = "rate_limited"
    ReasonForbidden          = "forbidden"
    ReasonSealed             = "sealed"
    ReasonDisabled           = "disabled"
    ReasonExpired            = "expired"
    ReasonInvalidCSRF        = "invalid_csrf"
    ReasonInvalidMasterKey   = "invalid_master_key"
)
```

**`UserAgent` フィールドは持たない。** 攻撃者が自由に設定できる文字列であり、
**型付き allowlist はフィールド名を制限するだけで、値の安全性を保証しない。**

### 5.5 攻撃者制御の文字列を記録しない

**`actor` / `target` / `detail` に、攻撃者が制御できる生の入力を入れてはならない。**

存在しない `client_id` / `username` での認証失敗:

- **`actor` は `"anonymous"`。** 生の入力値を記録しない
- 相関が必要な場合、**`detail.subject_digest` に
  `hex(SHA-256(input)[:8])` を入れる**(16 文字固定、制御文字なし)

```go
func subjectDigest(input string) string {
    sum := sha256.Sum256([]byte(input))
    return hex.EncodeToString(sum[:8])
}
```

これにより「同じ存在しない client_id が繰り返し試行された」ことは追跡できるが、
生の入力値が DB に入ることはない。

---

## 6. 暗号設計

### 6.1 マスターキー (MK)

- **形式**: 32 バイトのランダム値を base64url(パディングなし)でエンコードした文字列
- **生成**: `hokora gen-key` が `crypto/rand` で生成し、標準出力に一度だけ表示
- **保管**: 1Password の組織共有 Vault
- **ディスクへの保存**: **しない**

#### MK 入力の正規化と検証

**stdin / HTTP ボディから読んだ MK は、以下の順で処理する:**

```
1. 末尾の単一の LF または CRLF を除去する
   (op read や手入力は末尾改行を含みうる)
2. 厳密な base64url(パディングなし)としてデコードする
   → 失敗したら invalid_master_key
3. デコード結果が正確に 32 バイトであることを確認する
   → 違えば invalid_master_key
4. 読み込みに使ったバッファをゼロクリアする
```

**前後の空白を trim しない。** 意図しない文字が混入した MK を
「たまたま通す」ことを避けるため、除去するのは末尾の単一改行のみとする。

### 6.2 MK → KEK の導出

```
kek = argon2id(MK, kdf_salt, time=3, memory=64MB, threads=4, keyLen=32)
```

**この argon2 は unseal / rotate-master 時にのみ実行される。**
Machine API の認証経路では実行されない。

### 6.3 DEK

```
dek           = crypto/rand 32 bytes
dek_wrapped   = AES-256-GCM(kek, dek_nonce, dek, aad="hokora/keyring/v1")
```

**MK の検証**: unseal 時に `dek_wrapped` の復号を試み、
GCM の認証タグ検証が失敗すれば誤った MK と判定する。

**unseal 後、MK と KEK はゼロクリアする。DEK のみ保持する。**

### 6.4 Secret 値の暗号化

```
nonce      = crypto/rand 12 bytes
value_enc  = AES-256-GCM(dek, nonce, plaintext, aad)
```

**AAD は不変な整数 ID の固定幅バイナリ連結とする。**

```
aad = "hokora/item/v1"           (14 bytes, 固定長)
    || uint64be(item_id)         (8 bytes)
    || uint32be(version)         (4 bytes)
    || uint32be(dek_version)     (4 bytes)
```

**型変換の安全性:**

DB 側の `version` / `dek_version` は SQLite の `INTEGER`(int64)である。
`uint32` への変換で暗黙の切り捨てが起きると AAD の一意性が壊れる。

- **スキーマに `CHECK (version > 0 AND version <= 4294967295)` を置く**(§5.2)
- **`itemAAD()` は int64 を受け取り、範囲外ならエラーを返す**

```go
func itemAAD(itemID, version, dekVersion int64) ([]byte, error) {
    if version <= 0 || version > math.MaxUint32 {
        return nil, fmt.Errorf("version out of range: %d", version)
    }
    if dekVersion <= 0 || dekVersion > math.MaxUint32 {
        return nil, fmt.Errorf("dek_version out of range: %d", dekVersion)
    }
    if itemID <= 0 {
        return nil, fmt.Errorf("item_id out of range: %d", itemID)
    }
    // ...
}
```

M2 のテーブル駆動テストに境界ケース(0、負値、2^32、2^32-1)を含める。

**設計判断の根拠:**

初期案の `project_slug|env_slug|key|version` には、区切り文字の曖昧性、
slug の可変性、slug の再利用という 3 つの問題があった。
固定幅の不変 ID で全て解消される。

**AAD の実質的な価値:** DB への書き込みが可能な攻撃者は N1 として非目標であるため、
AAD の主な価値は「バックアップ復元のミスや実装バグによる暗号文の混線を
検出すること」である。

### 6.5 Nonce の管理

- 12 バイト、`crypto/rand` によるランダム生成
- **同一鍵で同一 nonce を再利用してはならない**
- ランダム nonce の衝突確率は、同一 DEK で 2^32 回の暗号化を行っても約 2^-33

### 6.6 メモリ上の鍵の扱い

- `Seal()` 時に DEK をゼロクリア
- unseal 完了時に MK と KEK をゼロクリア
- stdin / HTTP ボディから読んだ MK のバッファもゼロクリア
- **Go の GC がコピーを残す可能性は排除できない。best effort である**
- **`mlockall` により swap には出ない**(§4.2)
- **core dump / kdump は運用で止める**(THREAT_MODEL §5.3)

### 6.7 MK のローテーション

**実行経路: admin socket 経由のみ。全体を専用 mutex で直列化する(C10)。**

#### リクエスト形式

```
POST /rotate-master
Content-Type: application/octet-stream
Content-Length: <= 2048

<現行 MK>\n<新 MK>\n
```

- **改行区切りの 2 行**
- **サイズ上限 2 KB**(`MaxBytesReader`)
- 各行は §6.1 の正規化・検証を適用する
- 行数が 2 でなければ 400

#### 手順(クラッシュ安全性を含む)

```
1. 【人間】hokora gen-key で新 MK を生成し、stdout に表示
2. 【人間】1Password に保存する
3. 【人間】保存できたことを確認する      ← ここが重要
4. 【人間】現行 MK と新 MK を rotate-master に投入
5. 【hokora】専用 mutex を取得(C10)
6. 【hokora】現行 MK で KEK を導出し、DEK をアンラップ
   → 失敗したら中止(現行 MK が誤り)
7. 【hokora】新 MK で新 KEK を導出し、DEK を再ラップ
8. 【hokora】新しい dek_wrapped で復号できることを検証
   → 失敗したら中止
9. 【hokora】SQLite トランザクション内で keyring を更新 + 監査ログ
10.【hokora】commit 後、新しい keyring から DEK を再アンラップして検証
11.【hokora】全ての鍵素材をゼロクリア、mutex を解放
12.【人間】新しいバックアップを取得し、復元テストを行う(R15)
13.【人間】旧バックアップを廃棄してから、1Password の旧 MK を削除する
```

**重要な設計判断:**

- **`rotate-master` は新 MK を生成しない。** 生成は `hokora gen-key`(DB に触らない)
- 理由: 「生成 → DB 更新 → 1Password 保存前にクラッシュ」で全データが
  復旧不能になる事故を防ぐ。**1Password への保存を人間が確認してから
  rotate を実行する**
- **手順 9 が失敗した場合、旧 MK が引き続き有効である**(トランザクションのため)
- **手順 12〜13 が R15 の緩和策である。** 旧 MK を削除する前に、
  新 MK で復元できるバックアップが存在することを確認する

**secret の再暗号化は不要**(envelope encryption の利点)。

### 6.8 DEK のローテーション

Phase 3。

---

## 7. 認証

### 7.1 Machine Identity(クライアント用)

#### なぜ argon2 ではなく SHA-256 か

`client_secret` は **32 バイトの `crypto/rand` 由来のランダム値** である。
辞書攻撃やブルートフォースの対象にならない。

argon2 のような意図的に重い KDF は低エントロピーな秘密を守る道具であり、
高エントロピーな秘密には無意味なコストでしかない。それどころか、
**未認証で高頻度に呼べる Machine API の認証経路に 64MB × 数百 ms の計算を
持ち込むことで、DoS 増幅器を作ってしまう。**

したがって `client_secret` の検証は `crypto/sha256` +
`subtle.ConstantTimeCompare` で行う。

**この判断が成立する前提条件(不変条件):**

> **`client_secret` はサーバーが `crypto/rand` で生成したものに限る。
> ユーザーによる指定・インポートを許す API / 画面を実装してはならない。**

**注:** Web UI のログインと unseal もリクエスト経路だが、これらは
VPN 内からのみ到達可能(B1)であり、かつ argon2 の同時実行は semaphore で
制限される(§7.4)。**「リクエスト経路で argon2 を使わない」ではなく、
「未認証で高頻度に呼べる経路(Machine API 認証)で argon2 を使わない」**
が正確な原則である。

#### フロー

```
1. POST /v1/auth/token { "client_id": "...", "client_secret": "..." }

2. サーバー(read lock 内で完結、C6):
   - sealed なら 503(検証を行わない)
   - client_id で machine を検索
   - 存在しない場合も dummy hash 計算(タイミング攻撃対策)
   - SHA-256(client_secret) を ConstantTimeCompare で検証
   - disabled なら失敗
   - 監査ログを記録(fail closed)
   - 成功 → トークンを store に追加

3. { "token": "...", "expires_in": 900 }
```

#### トークンの仕様

- 32 バイトのランダム値(`crypto/rand`)を base64url エンコード
- **JWT は使わない**
- 有効期限 15 分
- **更新機構は持たない**
- **メモリ上の map に SHA-256 ハッシュで保持する**
- **map には上限を設ける**(§7.4)

```go
type tokenStore struct {
    mu     sync.Mutex
    tokens map[[32]byte]tokenInfo
    max    int
}

type tokenInfo struct {
    machineID int64
    expiresAt time.Time
}
```

**期限判定は lookup 時に行う。**

```go
func (s *tokenStore) Lookup(token []byte) (int64, bool) {
    h := sha256.Sum256(token)
    s.mu.Lock()
    defer s.mu.Unlock()
    info, ok := s.tokens[h]
    if !ok || !time.Now().Before(info.expiresAt) {   // ← 期限を必ず検査
        return 0, false
    }
    return info.machineID, true
}
```

**1 分ごとの sweep はメモリ掃除であって、認証上の期限判定ではない。**
sweep のみに依存すると、トークンが最大 1 分余分に使えてしまう。

**`DeleteByMachine(id)`** を持つ(C8 で使用)。

#### 認可の再検査

§4.5 の通り。

### 7.2 人間ユーザー(Web UI 用)

- パスワード認証(**argon2id**)
- セッション Cookie
- **トークンは SHA-256 ハッシュで DB 保存**
- **Machine Identity とは完全に別系統**
- **ログイン成功時にセッション ID を再生成する**
- **存在しない username に対しても dummy argon2 を実行する**
- **C9 の再読検証を行う**(§4.4)

**ロール:** admin のみ。

#### argon2id のパラメータ

| 項目 | 値 |
|------|-----|
| time | 3 |
| memory | 64 MB |
| threads | 4 |
| salt 長 | 16 バイト(`crypto/rand`) |
| hash 長 | 32 バイト |
| パスワード最大長 | **1024 バイト**(超えたら 400。DoS 対策) |
| パスワード最小長 | 12 文字 |

**保存形式: PHC 文字列形式。**

```
$argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
```

パラメータを保存形式に含めることで、将来パラメータを変更しても
既存のハッシュを検証できる。

#### セッションの期限

| 種類 | 値 | 判定 |
|------|-----|------|
| 絶対期限 | 12 時間 | `expires_at` |
| idle 期限 | 2 時間 | `last_seen_at` |

**両方を各リクエストで検査する**(§4.5)。sweep に依存しない。

#### Cookie の設定

```
Set-Cookie: __Host-hokora_session=<raw token>;
            Path=/; HttpOnly; Secure; SameSite=Strict
```

- **`__Host-` prefix**(Domain 属性なし、Path=/、Secure が強制される)
- logout 時は DB 側のセッションレコードを削除する

### 7.3 CSRF 対策

#### 設計判断: セッショントークンから導出する

初期案の `sessions.csrf_hash` にハッシュを保存する設計は **実装できない**。
synchronizer token パターンは、サーバーがフォーム描画時に **生のトークンを
HTML に埋め込む** ことを前提とするが、ハッシュしか保存していなければ
埋め込む値がない。

**採用する方式: セッショントークンからの導出。**

```go
func csrfToken(rawSessionToken []byte) string {
    h := sha256.New()
    h.Write([]byte("hokora/csrf/v1"))
    h.Write(rawSessionToken)
    return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
```

サーバーは毎リクエスト、Cookie から取得した **生の** セッショントークンから
CSRF トークンを再計算する。

**この方式の性質:**

- **DB に保存しない**(P6)
- DB 漏洩から raw session を復元できない(SHA-256 の preimage 耐性)
- CSRF token 漏洩から raw session を復元できない(同上)
- セッション再生成時に自動でローテーション
- 複数タブ・古いフォームでも安定

**位置づけ:** `__Host-` prefix + `SameSite=Strict` の時点で、現代のブラウザに
対する CSRF はほぼ塞がっている。CSRF トークンは多層防御の一層である。
だからこそ、複雑な状態管理を持ち込む価値がなく、stateless な導出が釣り合う。

#### ログイン POST(pre-auth)

**Fetch Metadata / Origin による検証。**

```
1. Sec-Fetch-Site: same-origin であることを要求
2. Sec-Fetch-Site が存在しない場合、Origin ヘッダを検証:
   - scheme / host / port が完全一致すること
   - Origin: null は拒否
3. 両方が欠けている場合は拒否
```

**Origin の「存在確認」ではなく、完全一致の検証を行うこと。**

**pre-auth セッションを作る方式は採らない。**

### 7.4 リソース制限(N7 に対する基本対策)

#### レート制限

| 対象 | 制限 | キー |
|------|------|------|
| `POST /v1/auth/token` | 30 回/分 | **送信元 IP**(第一段) |
| `POST /v1/auth/token` | 10 回/分 | client_id(第二段) |
| Web UI ログイン | 20 回/分 | **送信元 IP**(第一段) |
| Web UI ログイン | 5 回/分 | username(第二段) |
| unseal(socket / Web) | 3 回/分 | グローバル |

**送信元 IP を第一段に置くことが重要である。**

#### map の上限

レート制限とトークンの map は、**最大件数を設ける**。LRU で追い出す。
期限切れエントリは定期 sweep で削除する。

**注意: 上限つき map は制限の回避手段にもなる。** 多数の送信元 IP を持つ攻撃者は、
map を埋めることで正規のバケットを追い出し、カウンタをリセットできる。
これはプロセス内レート制限の原理的限界であり、**N7 の枠内として受容する**。

上限つき map は「メモリ枯渇を防ぐ」ためのものであり、
「制限を保証する」ものではない。

#### 同時実行制限

```go
var argon2Sem = make(chan struct{}, 4)
```

argon2 が実行されるのは:
- unseal / rotate-master 時の KEK 導出
- Web UI のログイン(パスワード検証)

Machine 認証は SHA-256 なので通らない。

#### HTTP サーバーの設定

```go
srv := &http.Server{
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      15 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    8 << 10,
}
```

**timeout がゼロだと無制限になる。**

#### ボディサイズ上限

| 対象 | 上限 |
|------|------|
| `/v1/auth/token` の JSON | 4 KB |
| unseal のボディ | 1 KB |
| **rotate-master のボディ** | **2 KB** |
| Web UI のフォーム | 128 KB |
| secret の値 | **64 KB**(§5.3) |
| パスワード | **1024 バイト**(§7.2) |

`http.MaxBytesReader` を全ての listener で使う。

### 7.5 credential 再発行・パスワード変更時の既存トークン

| 操作 | 追加で行うこと | 並行制御 |
|------|---------------|---------|
| `machine.rotate_secret` | **当該 machine の全トークンを store から削除** | **C8(write lock)** |
| `machine.disable` | 同上 | **C8** |
| `user.password_change` | **当該 user の全セッションを DB から削除**(実行者自身のセッションは再生成) | **C9(tx 内で hash 再読)** |
| `user.disable` | 同上 | C9 |
| `grant.delete` | (§4.5 の再検査で即座に効く) | 不要 |

**監査の失敗時セマンティクス:** これらはすべて **fail open**
(THREAT_MODEL §10.4)。漏洩対応の緊急操作であり、監査障害で止めてはならない。

---

## 8. API 仕様

### 8.1 Machine API(:9443、machineMux)

**全レスポンスに `Cache-Control: no-store`。**

#### `POST /v1/auth/token`

```jsonc
// Request
{ "client_id": "app-prod", "client_secret": "..." }
// 200
{ "token": "...", "expires_in": 900 }
// 401(client_id 不在と secret 不一致を区別しない)
{ "error": "invalid_credentials" }
// 429 / 503
{ "error": "rate_limited" } / { "error": "sealed" }
```

#### `GET /v1/secrets?project={slug}&env={slug}`

```jsonc
// 200
{ "project": "myapp", "env": "prod", "secrets": { "DATABASE_URL": "..." } }
// 403(grant なし・論理削除済みのいずれも同じ。§11.1)
{ "error": "forbidden" }
```

**監査ログは key ごとに 1 レコード、1 トランザクションで N 行 INSERT。**
commit が成功してから、レスポンスの送信を開始する。

#### `GET /v1/secrets/{key}?project={slug}&env={slug}`

**常に最新バージョン。version パラメータは存在しない。**

#### `GET /healthz`

認証不要。**バージョン文字列を返さない。**

### 8.2 Admin socket(adminMux)

| メソッド | パス | ボディ | 上限 |
|---------|------|-------|------|
| POST | `/unseal` | MK 1 行 | 1 KB |
| POST | `/seal` | なし | — |
| GET | `/status` | — | — |
| POST | `/rotate-master` | 現行 MK + 新 MK の 2 行(§6.7) | 2 KB |

### 8.3 Web UI(:8443、uiMux、VPN IF のみ)

**全レスポンスに以下のヘッダ:**

```
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000
```

#### ルーティング

| メソッド | パス | 説明 | sealed 時 |
|---------|------|------|-----------|
| GET | `/ui/static/*` | CSS / JS(**認証不要**。§9.4) | 配信 |
| GET | `/ui/login` | ログインフォーム | 表示可 |
| POST | `/ui/login` | ログイン(Fetch Metadata 検証) | 処理可 |
| POST | `/ui/logout` | ログアウト | 処理可 |
| **GET** | **`/ui/password`** | **パスワード変更フォーム** | **表示可** |
| **POST** | **`/ui/password`** | **パスワード変更(§7.5)** | **処理可** |
| GET | `/ui/unseal` | unseal フォーム | 表示可 |
| POST | `/ui/unseal` | unseal 処理 | 処理可 |
| GET | `/ui/` | ダッシュボード(project 一覧) | `/ui/unseal` へ |
| POST | `/ui/projects` | project 作成 | 同上 |
| GET | `/ui/projects/{slug}` | environment 一覧 | 同上 |
| POST | `/ui/projects/{slug}/delete` | project 論理削除 | 同上 |
| POST | `/ui/projects/{slug}/environments` | environment 作成 | 同上 |
| GET | `/ui/projects/{slug}/{env}` | item 一覧(**マスク済み**) | 同上 |
| POST | `/ui/projects/{slug}/{env}/delete` | environment 論理削除 | 同上 |
| POST | `/ui/projects/{slug}/{env}/items` | item 作成 | 同上 |
| POST | `/ui/projects/{slug}/{env}/items/{key}` | item 更新 | 同上 |
| POST | `/ui/projects/{slug}/{env}/items/{key}/reveal` | 平文表示 | 同上 |
| POST | `/ui/projects/{slug}/{env}/items/{key}/delete` | item 論理削除 | 同上 |
| GET | `/ui/projects/{slug}/{env}/items/{key}/history` | 履歴(マスク済み) | 同上 |
| POST | `/ui/.../history/{v}/reveal` | 過去版の平文表示 | 同上 |
| GET | `/ui/machines` | Machine 一覧 | 同上 |
| POST | `/ui/machines` | Machine 作成(**credential を一度だけ表示**) | 同上 |
| POST | `/ui/machines/{id}/rotate` | credential 再発行(**同上**) | 同上 |
| POST | `/ui/machines/{id}/disable` | 無効化 | 同上 |
| POST | `/ui/machines/{id}/grants` | grant 追加 | 同上 |
| POST | `/ui/machines/{id}/grants/{envID}/delete` | grant 削除 | 同上 |
| GET | `/ui/users` | ユーザー一覧 | 同上 |
| POST | `/ui/users` | ユーザー作成 | 同上 |
| POST | `/ui/users/{id}/disable` | 無効化 | 同上 |
| GET | `/ui/audit` | 監査ログ | 同上 |

#### 初回ログインのフロー

初期 admin は `must_change_pw = 1` である。**パスワード変更は sealed 状態でも
動作しなければならない**(初回セットアップ時は必ず sealed のため)。

```
ログイン
  ↓
must_change_pw = 1 なら /ui/password へリダイレクト
  ↓
パスワード変更(sealed でも可能)
  ↓
セッション再生成(§7.2)
  ↓
sealed なら /ui/unseal へ、unsealed なら /ui/ へ
```

---

## 9. Web UI の実装方針

### 9.1 平文の表示制御

- item 一覧では **常にマスク表示**
- **マスクは表示上の処理ではない。サーバーが値を返さない**
- 平文を見るには、明示的に「表示」ボタンを押す(`POST`)
- **監査ログの記録が成功してから** 平文をレスポンスに含める
- クリップボードコピー機能は実装しない

### 9.2 平文を表示するページ(bfcache 対策の対象)

以下は **平文を含むレスポンス**であり、bfcache 対策の対象である:

- item の reveal 結果
- 履歴の過去版 reveal 結果
- **Machine 作成時の credential 表示**
- **credential 再発行時の credential 表示**
- **`hokora init` 相当の初期 admin パスワード表示**(Web からは行わないが、
  将来追加する場合は対象)

### 9.3 bfcache 対策

**`Cache-Control: no-store` だけでは、bfcache による平文の再表示を防げない。**

Chrome は 2025 年 3〜4 月に、`Cache-Control: no-store` のページも
条件を満たせば bfcache に格納する変更を全ユーザーに展開した。
Cookie の変更があると evict されるが、**reveal ページは Cookie を変更しないため、
この保護は効かない**。

#### `location.reload()` は使えない

**reveal ページは POST のレスポンスである。** POST で生成されたドキュメントに
対する `location.reload()` は、ブラウザが「フォーム再送信の確認」ダイアログを
出す。**ユーザーがキャンセルすると、bfcache から復元された平文がそのまま
表示され続け、対策が無効化される。**

#### 採用する方式

**ページ種別を属性で渡し、平文ページは安全な GET URL へ退避する。**

```html
<!-- 平文を含むページ(reveal 結果、credential 表示) -->
<body data-bfcache="replace" data-bfcache-url="/ui/projects/myapp/prod">

<!-- 通常のページ -->
<body data-bfcache="reload">
```

```javascript
// static/bfcache.js
(function () {
    var body = document.body;
    var mode = body.getAttribute('data-bfcache') || 'reload';

    window.addEventListener('pageshow', function (e) {
        if (!e.persisted) return;

        if (mode === 'replace') {
            // 平文を含むページ: 即座に DOM から消してから退避する。
            // bfcache は DOM のスナップショットを復元するため、
            // 遷移完了までの間に古い平文が表示されうる。
            document.documentElement.textContent = '';
            location.replace(body.getAttribute('data-bfcache-url') || '/ui/');
        } else {
            location.reload();
        }
    });
})();
```

**設計の要点:**

1. **`persisted` を検出したら、まず DOM を消す。**
   bfcache は DOM と JS ヒープを含むページ全体のスナップショットを復元する。
   `pageshow` は復元時に発火するが、遷移が完了するまでの間に古い平文が
   表示されうる
2. **平文ページは `location.replace()` で安全な GET URL へ退避する。**
   `reload()` は POST の再送確認を招く
3. **通常のページは `location.reload()`。** 全ページ一律で `replace` すると、
   フォーム入力中のページで「戻る」がダッシュボード行きになり UX を壊す
4. **インラインではなく `static/bfcache.js`** として配信する
   (CSP の `script-src 'self'` を維持)

**M5 の完了条件は、ヘッダの確認だけでは不十分である。**
実ブラウザ(Chrome)で以下を確認すること:

- reveal → 別ページへ遷移 → 戻る → **平文が表示されない**
- **再送信確認ダイアログが出ないこと**(`replace` なので出ないはず)
- Machine 作成 → 遷移 → 戻る → **credential が表示されない**

**JavaScript が無効な環境では bfcache 対策が効かない。**
VPN 内の管理者ブラウザ前提なので受容するが、OPERATIONS.md に
「Web UI は JavaScript 有効を前提とする」と記載する。

### 9.4 静的アセット

- `/ui/static/style.css`、`/ui/static/bfcache.js`
- **認証不要**(ログインページでも読み込む必要があるため)
- **認証不要で配るのは `static/` のみ**
- `embed.FS` から配信

### 9.5 レスポンス圧縮を有効にしない

**CSRF トークンが全ページの HTML に埋め込まれる設計であるため、
レスポンス圧縮と攻撃者制御の反射文字列が同居すると、理論上 BREACH 系の
抽出対象になる。**

`net/http` はデフォルトで圧縮しないため現状は安全だが、
**将来「gzip を入れよう」となることを防ぐため、明示的に禁止する**(P2)。

### 9.6 テンプレート

- `html/template` の自動エスケープに依存する
- **`template.HTML` / `template.JS` / `template.URL` は使わない**
- CSP により多層防御する
- テンプレートは `embed.FS` で同梱し、起動時に一度だけパースする

---

## 10. CLI

```
hokora init                      # DB 初期化、MK 生成、初期 admin 作成
hokora gen-key                   # 新しい MK を生成して表示(DB に触らない)
hokora serve                     # サーバー起動(sealed 状態で起動)
hokora unseal --stdin
hokora seal
hokora status
hokora rotate-master             # §6.7

# クライアント側
hokora get KEY                   # 単一 secret を stdout へ(端末確認用)
hokora run -- ./myapp            # 環境変数に展開(移行用)
```

**`hokora export` は実装しない**(P2)。

**`hokora get` の位置づけ:** 端末での確認用である。
**`hokora get KEY > file` のようにファイル生成に使ってはならない**
(`export` を実装しない理由と同じ)。OPERATIONS.md に明記する。

**`hokora get` の credential 経路:** `/etc/hokora/credentials` は root:0600 なので、
人間が対話的に使う場合は `sudo hokora get` になる。日常的な確認は Web UI を
使うことを推奨する(OPERATIONS.md)。

### 10.1 unseal の実行例

```bash
# ローカル PC から、1Password 経由(推奨)
op read 'op://Infra/hokora/master-key' | ssh vps 'sudo -n hokora unseal --stdin'

# 手でペーストする場合
ssh -t vps 'sudo -n hokora unseal --stdin'
# → ペーストして Ctrl+D
```

**`sudo -n` を使う理由:** `sudo` がパスワードを要求すると、**stdin から
読もうとして MK を消費する可能性がある。** `-n`(non-interactive)を付け、
`hokora` コマンドに対する NOPASSWD の sudoers 設定を前提とする。

```
# /etc/sudoers.d/hokora
%hokora-admins ALL=(root) NOPASSWD: /usr/local/bin/hokora unseal --stdin, /usr/local/bin/hokora seal, /usr/local/bin/hokora status
```

**MK は以下の経路では絶対に渡さない:**

- コマンドライン引数(`ps` で全ユーザーから見える)
- 環境変数(`/proc/<pid>/environ` に残る、シェル履歴に残る)
- **`echo -n "$KEY" | ...`**(`echo` が外部コマンドの場合、argv に値が現れる)

### 10.2 クライアント側の設定

```bash
# /etc/hokora/credentials (0600, root:root)
HOKORA_ADDR=https://hokora.example.com:9443
HOKORA_CLIENT_ID=app-prod
HOKORA_CLIENT_SECRET=...
HOKORA_PROJECT=myapp
HOKORA_ENV=prod
```

```ini
[Service]
LoadCredential=hokora:/etc/hokora/credentials
ExecStart=/usr/local/bin/myapp
User=myapp
PrivateMounts=true          # THREAT_MODEL B7
LimitCORE=0                 # 推奨(THREAT_MODEL §5.4)
```

**注:** `$CREDENTIALS_DIRECTORY` はサービス実行 UID から読める。
T1-a の攻撃者もここから credential を取得できる(N2 として受容)。

### 10.3 `hokora run` の限界

**`hokora run` は環境変数に secret を展開するため、`/proc/<pid>/environ` から
T1-a の攻撃者が secret 値そのものを読める**(THREAT_MODEL R5)。

**これは V1 を無効化する。** `hokora run` は既存アプリケーションの移行用と
位置づけ、**Go アプリケーションでは SDK 方式を使うこと。**

---

## 11. Go SDK

### 11.1 credential の受け取り

**SDK は以下の順で credential を探す:**

```
1. 明示的な Option(WithCredentials(id, secret))
2. $CREDENTIALS_DIRECTORY/hokora  ← systemd LoadCredential= の展開先
3. 環境変数(HOKORA_CLIENT_ID / HOKORA_CLIENT_SECRET)
```

**手順 2 が systemd 環境での標準経路である。** `LoadCredential=hokora:/etc/hokora/credentials`
と組み合わせることで、アプリケーションのコード変更なしに credential を渡せる。

ファイル形式は `/etc/hokora/credentials` と同じ(`KEY=VALUE` の行)。

### 11.2 API

```go
// Package hokora provides a client for the hokora secret management server.
//
// Secrets fetched by this package are held in memory only and are never
// written to disk by the SDK itself.
//
// # Security
//
// This package does not protect against an attacker who has obtained the
// same OS user privileges as your application. Such an attacker can read
// the machine credential from $CREDENTIALS_DIRECTORY and fetch the same
// secrets, or read the process memory directly.
//
// This package also does not prevent the operating system from writing
// process memory to disk via swap, core dumps, or kernel crash dumps.
// See the project's threat model for details.
package hokora

// Client is a client for a hokora server.
type Client struct { /* ... */ }

// New creates a Client.
//
// Credentials are resolved in the following order:
//   1. WithCredentials option
//   2. $CREDENTIALS_DIRECTORY/hokora (systemd LoadCredential=)
//   3. HOKORA_CLIENT_ID / HOKORA_CLIENT_SECRET environment variables
func New(opts ...Option) (*Client, error)

// Fetch retrieves all secrets for the configured project and environment.
func (c *Client) Fetch(ctx context.Context) (*Secrets, error)

// Secrets holds fetched secret values in memory.
type Secrets struct { /* ... */ }

// Get returns the value for key as a byte slice.
// The returned slice aliases internal storage; do not modify it.
func (s *Secrets) Get(key string) (value []byte, ok bool)

// GetString returns the value for key as a string.
//
// Warning: Go strings are immutable, so a value obtained through this
// method cannot be zeroed by Zero. Prefer Get when the value's lifetime
// matters.
func (s *Secrets) GetString(key string) (value string, ok bool)

// MustGetString returns the value for key, panicking if it is absent.
func (s *Secrets) MustGetString(key string) string

// Zero overwrites the in-memory secret values.
//
// This is best-effort. Values returned by GetString cannot be zeroed, and
// the Go runtime may retain copies made during garbage collection.
func (s *Secrets) Zero()
```

**設計方針:**

- **内部は `[]byte` で保持する**
- **`Zero()` が best effort であることを godoc に明記する**
- **防御範囲を過大に書かない**(P7)。swap / core dump についても明記する
- ディスクへの書き込み機能を持たない
- キャッシュを持たない
- 依存は標準ライブラリのみ(Phase 2 の `WithMlockall()` を除く)
- **`InsecureSkipVerify` 相当のオプションを提供しない**
- godoc は英語

---

## 12. リポジトリ構成

```
hokora/
├── go.mod                   # module github.com/kan/hokora
├── LICENSE                  # Apache-2.0
├── NOTICE / README.md / SECURITY.md
├── AGENTS.md                # エージェント向け指示書(CLAUDE.md は @AGENTS.md を import するだけ)
├── Makefile / .goreleaser.yaml
│
├── main.go
├── cmd_init.go              # init / gen-key
├── cmd_serve.go
├── cmd_unseal.go            # unseal / seal / status
├── cmd_rotate.go            # rotate-master
├── cmd_client.go            # get / run
│
├── crypto.go                # KDF、AEAD、itemAAD、ゼロクリア
├── crypto_test.go
├── keyring.go               # MK/KEK/DEK、seal/unseal、並行制御(C1-C10)
├── keyring_test.go
├── mlock.go                 # mlockall(§4.2)
│
├── store.go                 # SQLite。DSN での PRAGMA 適用
├── store_test.go
├── schema.sql               # embed
├── migrate.go               # PRAGMA user_version
│
├── model.go                 # 構造体、slug/key/値のバリデーション
├── audit.go                 # action allowlist、AuditDetail、fail open/closed
├── audit_test.go
├── token.go                 # tokenStore(M3)
├── token_test.go
│
├── server.go                # 3 つの mux、2 つの listener、TLS リロード
├── server_test.go           # mux 分離のテスト
├── api.go
├── api_test.go
├── admin.go
├── auth.go                  # Machine 認証
├── auth_test.go
├── session.go               # セッション、CSRF 導出
├── session_test.go
├── ratelimit.go
├── ratelimit_test.go
│
├── ui.go
├── ui_test.go
├── templates/               # embed
├── static/
│   ├── style.css
│   └── bfcache.js           # §9.3
│
├── sdk/
│   ├── client.go
│   ├── secrets.go
│   └── client_test.go
│
└── docs/
    ├── THREAT_MODEL.md / DESIGN.md / ROADMAP.md / OPERATIONS.md
```

---

## 13. 代替案の検討

### 13.1 SOPS + age

**利点:** サーバー運用が不要、可用性問題がない、**secret zero problem の性質が
異なる**(常時稼働するサービスへの認証情報が不要)、枯れている。

**採用しなかった理由:** **Web UI による閲覧・編集ができない**、更新に
git の commit / push / deploy が必要、監査ログが git log に依存する。

**評価:** hokora の要件から Web UI を外すなら、SOPS + age が合理的な選択である。
**README に明記する。**

### 13.2 HashiCorp Vault

規模に対して機能が過剰。運用の複雑さが利便性に見合わない。ライセンス(BSL)。

**Vault も secret zero problem を解いていない**(AppRole の SecretID)。

### 13.3 Infisical(継続利用)

構成の重さ、機能過剰。**セキュリティ上の理由ではない。**

**以下の場合は Infisical に戻るべき:** 組織拡大による細かい権限管理、
外部サービス連携、自動ローテーション。

### 13.4 クラウドの Secret Manager

VPS 上の環境では外部依存が増える。**ただし AWS 上のワークロードに限れば、
IAM Role により secret zero problem を解ける**という決定的な利点がある。

### 13.5 root で fetch → 権限降下 → exec するランチャー

**採用しなかった理由:** Go での setuid 降下は落とし穴が多い。
守れる範囲が限定的(N4 により secret はどのみちメモリにある)。
業界標準を超えた防御であり、複雑性に見合わない。

**Phase 3 で再検討の余地はある。**

---

## 14. 未解決の設計課題

| # | 課題 | 状態 |
|---|------|------|
| Q1 | TLS 証明書 | **確定**: Let's Encrypt DNS-01、**certbot は別ホスト**、versioned dir + symlink、SIGHUP、失敗時は旧証明書を維持 |
| Q2 | slug / key の文字種制限 | **確定**(M1): slug は `^[a-z0-9][a-z0-9-]{0,63}$`、key は `^[A-Z_][A-Z0-9_]{0,127}$`。slug は URL パスにそのまま載るため大文字・パス記号を排除し、key は環境変数名として展開されるため POSIX の変数名に収まる文字に限る。実装は `model.go` の `ValidateSlug` / `ValidateItemKey` |
| Q3 | 初期 admin パスワード | **確定**: stdout に一度だけ表示、`must_change_pw`、**sealed でも変更可能**(§8.3) |
| Q4 | 監査ログの保持期間 | **確定**: MVP では無限 |
| Q5 | MVP でのバックアップ手順 | **M6 で確定させる。** offline 手順。**`-wal` / `-shm` を含む全ファイルセットをコピーするか、停止後に WAL が消えていることを確認する。** 復元テストを完了条件に含める |
| Q6 | Web UI の DNS レコード | **M6 で確定させる。** 公開 DNS の `hokora.example.com` は Machine API の public IP。Web UI 用に VPN 内 IP を指す別レコード。**内部 IP が公開 DNS に載る軽微な情報漏れを受容することを明記** |
