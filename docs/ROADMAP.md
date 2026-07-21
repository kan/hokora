# hokora ロードマップ

前提: `docs/THREAT_MODEL.md`、`docs/DESIGN.md`

## マイルストーンの考え方

- **M1〜M6 が MVP**。ここまでで実運用に投入できる状態にする
- 各マイルストーンの完了条件を満たすまで次に進まない

### M3 の再編について(第4版)

第3版の M3 は、完了条件で tokenStore と audit.go を要求しながら、
それらを M4 の成果物としていたため、**物理的に完了できなかった**。

第4版では **audit core と tokenStore の基礎を M3 に移す**。理由:

- **unseal の監査は M3 の本質である**(fail closed / fail open の検証)
- **C6(トークン発行と seal の排他)は seal の設計そのもの**であり、
  tokenStore なしには検証できない
- argon2 semaphore は unseal で必要になる

M4 は「Machine API・認証・ネットワーク境界」に集中する。

### 外部レビューから得られた教訓

3 巡・計 6 件の外部レビューから:

> **このシステムで最初に壊れるのは暗号実装ではなく、
> 認証・ネットワーク境界・並行制御・運用手順の噛み合わせである。**

実際に壊れていたもの:

- `LoadCredential=` の挙動の誤解(防御が成立していなかった)
- listener の同居、mux の共有(境界が実装されていなかった)
- レート制限のキー選択(回避可能だった)
- セッショントークンの平文保存
- CSRF トークンのハッシュ保存(**実装不可能な設計だった**)
- swap / core dump / kdump(前提が崩れていた)
- **アプリサーバー側の swap / core dump**(同じ経路を別の場所で見落とした)
- bfcache(**対策が新しいブラウザ挙動によって無効化されていた**)
- **`location.reload()` が POST 結果ページで再送確認を招く**
- SQLite PRAGMA の接続単位性(RESTRICT が効かない可能性)
- **`/proc/self/environ` は T1-a で読める**(V1 の主張が誤っていた)
- **監査の fail closed を緊急遮断操作に適用していた**
- **C6 と同型の競合が revoke 系に残っていた**

**外部レビューは M2〜M6 の各段階で実施する。**

---

## M1: 基盤

**目的:** 骨格を作り、SQLite にアクセスできる状態にする。

**成果物:**

- `go.mod`(module path: `github.com/kan/hokora`)
- `main.go` — サブコマンドのディスパッチのみ
- `schema.sql` + `migrate.go`(**`PRAGMA user_version`**)
- `store.go` — **DSN による PRAGMA 適用**(DESIGN §3.1)
- `model.go` — 構造体、**slug / key / secret 値のバリデーション**
- `Makefile`、CI

**この段階で決めること(Q2):**

- project slug / env slug の文字種制限
- item key の文字種制限(環境変数として展開するため)

**完了条件:**

- `go build` で単一バイナリが生成される
- `hokora init` で SQLite ファイルが作られ、スキーマが適用される

**PRAGMA の実効性(DESIGN §3.1。これが効いていないと RESTRICT が無意味):**

- **複数の `*sql.Conn` を同時に取得し、それぞれで `PRAGMA foreign_keys` が
  1 を返すことをテストする**
- **接続を意図的に閉じて再取得し、再生成された接続でも 1 を返すことをテストする**
- **意図的に FK 違反を起こし、RESTRICT でエラーになることをテストする**
- `PRAGMA foreign_key_check` が空を返すことをテストする
- **DSN 方式で適用できなかった場合、接続後 hook 方式に切り替える**
  (`SetMaxOpenConns(1)` だけでは不十分。DESIGN §3.1)

**スキーマ:**

- **外部キーが全て `ON DELETE RESTRICT`**(`audit_logs` は FK を持たない)
- **`users` / `machines` に `deleted_at` がない**(disabled のみ)
- **部分 UNIQUE インデックスにより、論理削除された slug が再利用できる**
- **`item_versions.version` / `dek_version` に CHECK 制約**
  (uint32 範囲。itemAAD の型変換の安全性)
- **`audit_logs` に immutable ID カラムがある**(THREAT_MODEL §10.2)

**バリデーション:**

- slug / key の文字種
- **secret 値: 有効な UTF-8、NUL バイトなし、64 KB 以下**(DESIGN §5.3)
- `go test -race` が通る

---

## M2: 暗号レイヤー

**成果物:**

- `crypto.go`
  - `GenerateKey()`、`DeriveKEK()`、`sealBytes()`、`openBytes()`、`Zero()`
  - **`itemAAD(itemID, version, dekVersion int64) ([]byte, error)`** — 固定幅、
    **範囲外はエラー**
  - **MK の正規化と検証**(末尾改行の除去、base64url、32 バイト。DESIGN §6.1)
- `keyring.go` — DEK の生成とラップ
- `crypto_test.go`、`keyring_test.go`

**完了条件:**

- 暗号化 → 復号のラウンドトリップ
- **誤った MK での復号が確実に失敗する**
- **AAD が異なる場合に復号が失敗する**(item_id / version / dek_version のそれぞれ)
- **AAD が固定幅であり、曖昧性がない**
- **`itemAAD` の境界テスト**(0、負値、2^32、2^32-1)
- nonce が毎回異なる
- `Zero()` 後にバイト列がゼロである
- **MK の正規化テスト**(末尾 LF / CRLF あり・なし、不正な base64、
  31 バイト / 33 バイト)
- `go test -race` が通る

**レビュー時の確認ポイント:**

- `math/rand` が暗号用途で使われていないか
- nonce が再利用されていないか
- **AAD が固定幅バイナリで、型変換が検査されているか**
- エラーメッセージに値を含めていないか
- 比較に `ConstantTimeCompare` を使っているか

---

## M3: seal / unseal・並行制御・監査コア・トークン基盤

**第4版で範囲を拡大。** audit core と tokenStore の基礎を M3 に含める
(第3版では M4 に置いていたため、M3 が完了できなかった)。

**成果物:**

- `audit.go`(**コア部分**)
  - action allowlist、`AuditDetail` 型、`Reason` 定数
  - **immutable ID カラムへの記録**
  - **fail closed / fail open の分岐**(THREAT_MODEL §10.4)
  - **`subjectDigest()`**(攻撃者制御の文字列を記録しない。DESIGN §5.5)
- `token.go` — `tokenStore`
  - SHA-256 ハッシュで保持、**上限つき**、sweep
  - **`Lookup()` で期限を検査する**(sweep に依存しない。DESIGN §7.1)
  - **`DeleteByMachine(id)`**(C8 で使用)
- `keyring.go` に状態機械
  - `Unseal(mk []byte) error` — **成功時に MK/KEK をゼロクリア、DEK のみ保持**
  - `Seal() error` — DEK ゼロクリア、**トークンストアを空に**
  - `WithDEK(fn func(dek []byte) error) error` — read lock 保持
  - **`IssueToken()` も read lock 内で完結**(C6)
  - **`WithWriteLock(fn func() error) error`**(C8 で使用)
- `mlock.go` — **`mlockall`。失敗したら起動を中止**(DESIGN §4.2)
- `ratelimit.go`(**unseal 用の部分**)+ **argon2 semaphore**
- `admin.go` — Unix domain socket、**独立した adminMux**
- `cmd_serve.go`、`cmd_unseal.go`、`cmd_rotate.go`
- `cmd_init.go` に **`gen-key`**

**完了条件:**

- `hokora serve` が sealed 状態で起動する
- **`mlockall` に失敗したら起動が中止される**(`LimitMEMLOCK` 不足を検出)
- `op read '...' | ssh vps 'sudo -n hokora unseal --stdin'` で unsealed になる
- 誤ったキーでは unseal が失敗し、状態が変わらない
- **unseal 成功後、メモリ上に MK と KEK が残っていない**
- `hokora seal` で sealed に戻り、DEK がゼロクリアされる
- Admin socket のパーミッションが 0600 hokora:hokora
- **サーバーが非 root ユーザーで動作する**

**rotate-master(DESIGN §6.7):**

- **`rotate-master` が新 MK を生成しない**(`gen-key` で別途生成)
- **リクエスト形式が改行区切り 2 行、2 KB 上限**
- **rotate-master が失敗した場合、旧 MK が引き続き有効である**
- **rotate-master を並行実行しても直列化される**(C10)

**並行制御のテスト(race detector では検出できない):**

- unseal → トークン発行 → seal → unseal → **旧トークンが無効であること**
- **トークン発行と seal を並行実行し、seal 後に有効なトークンが存在しないこと**
  (goroutine を多数起動して繰り返す。C6)
- 復号処理の実行中に `Seal()` を呼び、**復号が完了してから seal されること**
- **ロックの取得順序が Vault.mu → tokenStore.mu で固定されていること**(C7)

**トークンの期限:**

- **`Lookup()` が期限切れトークンを拒否すること**(sweep を止めた状態でテスト)

**監査のセマンティクス(THREAT_MODEL §10.4):**

- **`unseal` は監査ログに書けなければ拒否される**(fail closed)
- **`seal` は監査ログに書けなくても実行される**(fail open)
  → 監査 DB を壊した状態で seal できることをテストする
- **`master.rotate` は fail closed**

**レビュー時の確認ポイント:**

- **MK をコマンドライン引数 / 環境変数から受け取る実装がないこと**
- stdin から読んだバッファが使用後にゼロクリアされているか
- **ドキュメントに `echo -n "$KEY" | ...` がないこと**
- **`sudo -n` が使われているか**(sudo が stdin から MK を消費しないため)

---

## M4: Machine API・認証・境界 ⚠️ 最重要

**成果物:**

- `auth.go`
  - **SHA-256 + ConstantTimeCompare**(argon2 は使わない)
  - 存在しない client_id への dummy hash 計算
  - **C8: `rotate_secret` / `disable` の「DB 更新 → トークン削除」を
    write lock 内で実行する**
- `ratelimit.go`(**Machine API 用**)
  - **送信元 IP を第一段**、client_id を第二段
  - **map に上限と TTL**
- `api.go` — `/v1/*`、`/healthz`
- `server.go`
  - **3 つの独立した mux**
  - **2 つの listener**(別ポート、別 bind)
  - **TLS の SIGHUP リロード、失敗時は旧証明書を維持**(DESIGN §3.7)
  - HTTP timeout、`MaxBytesReader`
  - ミドルウェア(ログ、パニックリカバリ、認証、`Cache-Control: no-store`)
- `store.go` に CRUD(**全祖先の `deleted_at IS NULL` 検査を含む**)

**完了条件:**

- Machine を作成し、`/v1/auth/token` でトークンが取得できる
- トークンで `/v1/secrets` から secret 群が取得できる
- **15 分後にトークンが無効になる**(`Lookup()` の期限検査)
- **grant のない environment へのアクセスが 403**
- **machine を disable すると、既存トークンでも即座に拒否される。**
  正規の `DisableMachine` は C8 によりトークンを削除するので **401**、
  トークンが残る経路(DB を直接更新した場合等)では §4.5 の再検査で **403**
- **grant を削除すると、既存トークンでも即座に 403**
- **project / environment を論理削除すると、配下の secret が
  Machine API から取得できなくなる**(THREAT_MODEL §11.1)
- **論理削除済みへのアクセスも 403**(grant なしと区別しない)
- sealed 状態で 503 が返り、**認証検証が実行されない**

**C8 のテスト(C6 と同型の競合。DESIGN §4.4):**

- **`rotate_secret` と旧 credential による認証を並行実行し、
  rotate 完了後に旧 credential 由来の有効トークンが存在しないこと**
- **`machine.disable` についても同様**

**mux 分離のテスト(DESIGN §4.1):**

- **Machine API listener で `/ui/login` が 404**
- **Web UI listener で `/v1/auth/token` が 404**
- **Web UI listener で `/healthz` が 404**

**その他:**

- **Web UI の bind address のデフォルトが 127.0.0.1**
- **`0.0.0.0` を Web UI に指定すると警告が出る**
- **ランダムな client_id を大量に送ってもレート制限が効く**(IP ベース)
- **`GET /v1/secrets` が key ごとに監査ログを記録する**
- **bulk fetch の監査が 1 トランザクションで N 行 INSERT される**
- **監査ログの記録が失敗したら secret を返さない**(fail closed)
- **監査 DB 障害時、認証は必ず拒否される**(fail closed)
- **`machine.disable` は監査失敗でも実行される**(fail open)
- **`machine.rotate_secret` は監査失敗でも実行される**(fail open)
- **`grant.delete` は M5 で実装する。** grant の CRUD は M5 の画面の成果物で
  あり、DESIGN §7.5 でも「§4.5 の再検査で即座に効く / 並行制御は不要」と
  されている。M4 に `machine.disable` / `rotate_secret` を前倒ししたのは
  C8(トークン発行との競合)が絡むためで、その理由は grant には無い
- **`/v1/secrets/{key}` に version パラメータが存在しない**
- **`/healthz` がバージョン文字列を返さない**
- **存在しない client_id での認証失敗が、actor `anonymous` +
  `subject_digest` で記録される**(生の入力値が DB に入らない)
- 全レスポンスに `Cache-Control: no-store`
- **TLS 証明書を SIGHUP でリロードできる。壊れた証明書では旧証明書を維持する**
- `go test -race` が通る

**レビュー時の確認ポイント:**

- **Machine 認証に argon2 を使っていないか**
- **`client_secret` をユーザーが指定できる経路がないか**(DESIGN §7.1 の不変条件)
- レート制限のキーが攻撃者制御値だけになっていないか
- **map に上限があるか**
- HTTP timeout が全て設定されているか
- item_versions が追記のみか
- **全てのクエリで祖先の `deleted_at` を検査しているか**
- **`AuditDetail` に攻撃者制御の文字列がないか**
- **`actor` / `target` に生の入力値が入っていないか**
- タイミング攻撃対策

---

## M5: Web UI ⚠️ 重要

**成果物:**

- `session.go`
  - **トークンは SHA-256 ハッシュで DB 保存**
  - **ログイン成功時のセッション ID 再生成**
  - **CSRF はセッショントークンから導出**(DB に保存しない)
  - **Fetch Metadata / Origin の完全一致検証**(pre-auth)
  - **C9: ログイン処理は tx 内で `password_hash` を再読して一致確認**
  - **絶対期限と idle 期限を各リクエストで検査**
- `ui.go` — 全ハンドラ(**DESIGN §8.3 のルーティング表の全て**)
- `templates/*.html`
- `static/style.css`、**`static/bfcache.js`**(DESIGN §9.3)

**画面:**

1. ログイン
2. **パスワード変更(`must_change_pw`。sealed 状態でも動作すること)**
3. unseal(sealed 時)
4. ダッシュボード(project 一覧)+ 作成 / 削除
5. project 詳細(environment 一覧)+ 作成 / 削除
6. environment 詳細(item 一覧、**常にマスク**)
7. item の作成・更新・削除
8. item の平文表示(`POST`、監査ログ)
9. バージョン履歴 + 過去版の平文表示
10. Machine 一覧・作成・無効化・**credential 再発行**・grant 追加/削除
11. ユーザー一覧・作成・無効化
12. 監査ログ閲覧

**完了条件:**

- **DESIGN §8.3 の全ルートが実装されている**
- **初回ログイン → パスワード変更 → セッション再生成 → unseal の
  フローが動く**(§8.3)
- **パスワード変更が sealed 状態でも動作する**
- ログイン → project 作成 → environment 作成 → item 作成 → 平文表示 →
  更新 → 履歴確認 → 削除 の一連の流れが動く
- sealed 状態でログインでき、Web UI から unseal できる
- **CSRF トークンがセッショントークンから導出され、DB に保存されていない**
- CSRF トークンなしの POST が全て拒否される
- **ログイン POST の Origin 検証が scheme / host / port の完全一致である**
- **`Origin: null` が拒否される**
- **`Sec-Fetch-Site` と `Origin` の両方が欠けている場合、拒否される**
- **ログイン成功時にセッション ID が再生成される**
- **DB に平文のセッショントークンが保存されていない**
- **セッションの絶対期限(12 時間)と idle 期限(2 時間)が
  各リクエストで検査される**(sweep に依存しない)
- **ユーザーを disable すると既存セッションが即座に無効になる**
- **一覧画面の HTML に平文の secret が含まれない**
- CSP が設定され、CDN からの読み込みが一切ない
- **レスポンス圧縮が有効になっていない**(DESIGN §9.5)
- **平文表示が監査ログに記録される**
- **`user.password_change` / `user.disable` が監査失敗でも実行される**(fail open)
- `go test -race` が通る

**C9 のテスト(DESIGN §4.4):**

- **`password_change` と旧パスワードによるログインを並行実行し、
  変更後に旧パスワード由来の有効セッションが存在しないこと**

**bfcache のテスト(DESIGN §9.3。ヘッダ確認では不十分):**

**実ブラウザ(Chrome)で確認すること:**

- **reveal → 別ページへ遷移 → 戻る → 平文が表示されない**
- **再送信確認ダイアログが出ない**(`location.replace()` を使うため)
- **Machine 作成 → 遷移 → 戻る → credential が表示されない**
- **credential 再発行 → 遷移 → 戻る → credential が表示されない**
- `static/bfcache.js` が全ページで読み込まれている
- CSP の `script-src 'self'` を維持している(インライン script でない)
- **平文ページは `data-bfcache="replace"`、通常のページは `"reload"`**

**レビュー時の確認ポイント:**

- `template.HTML` / `template.JS` / `template.URL` が使われていないか
- Cookie に `__Host-` prefix、`HttpOnly`、`Secure`、`SameSite=Strict`
- Cookie に `Domain` 属性がない
- 一覧画面のレスポンスに平文が含まれていないか
- CSRF の比較が `ConstantTimeCompare` か
- **存在しない username にも dummy argon2 が実行されるか**
- **argon2 の同時実行が semaphore で制限されているか**
- **argon2id のパラメータが PHC 文字列形式で保存されているか**
- **パスワードの最大長(1024 バイト)が検証されているか**

---

## M6: クライアント(SDK / CLI)・運用

**成果物:**

- `sdk/client.go`、`sdk/secrets.go`
  - **credential の解決順序: Option → `$CREDENTIALS_DIRECTORY/hokora` →
    環境変数**(DESIGN §11.1)
  - **内部は `[]byte`**
  - **`Zero()` が best effort であることを godoc に明記**
  - **swap / core dump についても godoc に明記**(P7)
  - **`InsecureSkipVerify` 相当を提供しない**
- `cmd/hokora-client/` — クライアント専用バイナリ `hokora-client`(`get` / `run`)。
  **標準ライブラリ + sdk のみに依存**(`sdk_deps_test.go` で検査)
- `docs/OPERATIONS.md` — Runbook

**Runbook に含める内容(必須):**

| 項目 | 内容 |
|------|------|
| 初期セットアップ | `hokora init` → 初回ログイン → パスワード変更 → unseal |
| **systemd unit(hokora)** | **`LimitCORE=0`、`LimitMEMLOCK=infinity`、`User=hokora`、ハードニング設定の完全な例** |
| **systemd unit(アプリ)** | **`PrivateMounts=true`(B7)、`LimitCORE=0`(推奨)、`LoadCredential=`** |
| **swap** | **システム全体の swap は無効化しない。hokora は mlockall で対応(§5.3)。暗号化 swap を使う場合は ephemeral key 方式に限る** |
| **core dump** | **systemd-coredump の無効化** |
| **kdump** | **無効化の確認手順**(`systemctl is-enabled kdump`、`/sys/kernel/kexec_crash_loaded`、`/sys/kernel/kexec_crash_size`)**と、有効だった場合の無効化**(`systemctl disable --now kdump`、`grubby --update-kernel=ALL --remove-args=crashkernel`)。**kernel panic 調査時の一時有効化 → 調査 → 再無効化の例外運用** |
| **firewalld** | **Machine API(:9443)をアプリサーバー IP のみに制限**(B3) |
| **TLS 証明書** | **certbot を別ホストで実行**(B6)。versioned directory + symlink による**ペア単位の原子的切り替え**(DESIGN §3.7)、deploy hook、SIGHUP、**リロード失敗時は旧証明書を維持** |
| **DNS レコード(Q6)** | 公開 DNS の `hokora.example.com` は Machine API の public IP。Web UI 用に VPN 内 IP を指す別レコード。**内部 IP が公開 DNS に載る軽微な情報漏れを受容することを明記** |
| **sudoers** | **`sudo -n` を前提とした NOPASSWD 設定**(DESIGN §10.1)。sudo が stdin から MK を消費するのを防ぐ |
| unseal 手順 | **開発者でないメンバーでも実行できる粒度で** |
| **バックアップ手順(Q5)** | **offline: seal → 停止 → 接続クローズ確認 → コピー → 起動 → unseal。`-wal` / `-shm` を含む全ファイルセットをコピーするか、停止後に WAL が消えていることを確認する** |
| **復元テスト手順** | **R3 の緩和策が実態を持つために必須** |
| **復元時の注意(R16)** | **古いバックアップを復元すると、古い credential・削除済み grant・変更前のパスワード・古いセッションが復活する。復元後に全セッションを削除し、バックアップ取得後の credential / grant / user 変更を再適用する** |
| MK 紛失時の対応 | 復旧不能であることの明示 |
| **MK のローテーション手順(R15)** | **`gen-key` → 1Password に保存 → 保存を確認 → `rotate-master` → 新バックアップ取得 → 復元テスト → 旧バックアップ廃棄 → 旧 MK を削除。この順序が重要**(DESIGN §6.7) |
| **TLS 秘密鍵漏洩時の対応** | 証明書の失効と再発行 |
| **侵害検知時の対応(R13)** | **revoke は「今後の取得」しか止めない。当該 grant 範囲の secret を個別にローテーションする** |
| **監査ログの見方** | V4 は運用によってのみ実現される。**`success` は「送信を開始した」の意味**(§10.5) |
| **grant の最小化** | V2 は運用によってのみ実現される |
| **`hokora-client get` の位置づけ** | **端末確認用。`> file` でファイル生成に使わない** |
| **`hokora-client run` の限界** | **T1-a で `/proc/<pid>/environ` から secret が読める。Go アプリでは SDK を使う**(R5) |
| **Web UI は JavaScript 有効を前提とする** | bfcache 対策のため(DESIGN §9.3) |
| トラブルシューティング | |

**完了条件:**

- **SDK が `$CREDENTIALS_DIRECTORY/hokora` から credential を読める**
- SDK からメモリ上に secret を取得できる
- `hokora-client run -- ./app` で環境変数に展開して子プロセスが起動する
- `hokora-client get KEY` が stdout に値を出力する
- **`hokora-client` が標準ライブラリ + sdk のみに依存する**(サーバー依存を積まない)
- **Runbook に従って、初見の人間が unseal できる**
- **Runbook に従ってバックアップを取得し、そこから復元できることを実際に確認する**
- **systemd unit の例に `LimitCORE=0` と `LimitMEMLOCK=infinity` が含まれる**
- **firewalld の設定手順が含まれる**
- **kdump の確認・無効化手順が含まれる**
- `go test -race` が通る

---

## M7: リリース準備

**成果物:**

- `README.md`
  - hokora が何をするか
  - **hokora が何をしないか**(THREAT_MODEL へのリンク)
  - **secret zero problem を解かないことの明示**
  - **T1 に対する防御が部分的であることの明示**
  - **`hokora-client run` では V1 が成立しないことの明示**
  - **revoke は今後の取得しか止めないことの明示**
  - **swap(mlockall)/ core dump / kdump / firewalld の運用要件が
    必須であることの明示**
  - **アプリサーバー側のディスク漏洩は hokora の管理外であることの明示**
  - **Web UI が不要なら SOPS + age を使うべき、という記述**
  - インストール、クイックスタート
- `LICENSE`(Apache-2.0)、`NOTICE`、`SECURITY.md`
- `.goreleaser.yaml`、GitHub Actions
- `CONTRIBUTING.md`

**完了条件:**

- タグを打つとバイナリがリリースされる
- **README を読んで、第三者が「hokora は自分の脅威モデルに合うか」を判断できる**

---

## Phase 2

| 項目 | 動機 |
|------|------|
| **SDK の `WithMlockall()` Option** | **アプリサーバー側の swap 経由の漏洩を減らす(THREAT_MODEL §5.4)。デフォルト無効。`LimitMEMLOCK=infinity` が必要。プロセス全メモリが常駐することを godoc に明記。`golang.org/x/sys` の依存追加を伴う。効くのは swap のみで、core dump / kdump は運用で止める必要があることも明記** |
| SQLite の `VACUUM INTO` によるオンラインバックアップ | M6 の offline 手順を置き換える |
| mTLS によるクライアント認証 | 多層防御。**N2 は解決しない** |
| Ansible role による deploy | 既存の運用に合わせる |
| Prometheus メトリクス | 監視の統合 |

---

## Phase 3(検討のみ)

| 項目 | 判断基準 |
|------|---------|
| DEK ローテーション | 鍵の運用期間が問題になったら |
| 監査ログ / item_versions の purge | サイズが問題になったら |
| project 単位の権限管理 | 組織が 3 名以上になったら |
| SPA フロントエンド | Web UI の操作頻度が上がったら |
| OIDC / SSO | 組織が拡大したら |
| root fetch + 権限降下ランチャー | N2 を部分的に解きたくなったら(DESIGN §13.5) |
| 冗長化 | **これが必要なら、hokora ではなく Vault を使うべき** |

---

## 開発の進め方

- 各マイルストーンごとに PR を分ける
- テストは実装と同時に書く
- `go test -race` を常に通す
- `govulncheck` を CI に入れる
- **M2〜M6 は実装後に外部レビューを通す**
- **特に M4 と M5 は最重要**
- **並行制御は `go test -race` では足りない。**
  C6 / C8 / C9 / C10 の意味上の競合を明示的にテストする
