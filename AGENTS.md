# AGENTS.md

このファイルは AI エージェントがこのリポジトリで作業する際の指示書である。
`CLAUDE.md` は本ファイルを import するだけの薄いファイルである。

---

## プロジェクト概要

**hokora** は、単一組織向けのミニマルな秘匿情報管理サーバー。Go 製、単一バイナリ。

**目的:** アプリケーションが秘匿情報の設定ファイルを必要としない状態にし、
アプリケーションサーバーが持つ長期的な秘密を、N 個の secret から
1 個の失効可能な machine credential に置き換える。

**hokora が解決しないこと:**

- **secret zero problem** — アプリユーザー権限を取得した攻撃者は、
  当該 machine に grant された secret を取得できる。Infisical も Vault も同じ
- **アプリサーバー側のディスク漏洩** — swap / core dump / kdump は hokora の管理外
- **revoke は「今後の取得」しか止めない** — 既に取得された secret は
  個別にローテーションが必要

**過大な防御を主張する実装・記述をしないこと。**

**module path:** `github.com/kan/hokora`

---

## 必読ドキュメント

| ファイル | 内容 |
|---------|------|
| `docs/THREAT_MODEL.md` | 何から守り、何を守らないか。**全ての設計判断の根拠** |
| `docs/DESIGN.md` | アーキテクチャ、データモデル、暗号設計、API 仕様 |
| `docs/ROADMAP.md` | マイルストーン分割と各段階の完了条件 |

**迷ったら THREAT_MODEL.md に戻ること。**

---

## この設計は 3 巡の外部レビューを経ている

初期設計は 3 巡・計 6 件の外部レビューを受けた。
**発見された問題と教訓を、同じ種類の誤りを繰り返さないために記録する。**

| 発見された問題 | 教訓 |
|---------------|------|
| `LoadCredential=` はサービス実行 UID から読めるため、T1 防御が成立していなかった | **仕組みの挙動を確認せずに防御を主張しない** |
| **`/proc/self/environ` はファイルであり、パストラバーサルで読める。`hokora run` では T1-a で secret 値そのものが漏れる** | **「メモリ上だから安全」は経路を確認してから言う** |
| Machine API と Web UI が同一 listener だった | **信頼境界は実装で強制する。文書に書くだけでは境界ではない** |
| listener を分けても、同じ mux を渡せば両方のポートで両方のパスが応答する | **分離は最後まで貫かないと意味がない** |
| レート制限のキーが攻撃者制御値で、argon2 が DoS 増幅器になっていた | **レート制限のキーは攻撃者が変えられない値を第一段に** |
| セッショントークンが平文保存され、T3 の穴になっていた | **bearer credential は全てハッシュで保存する** |
| CSRF トークンをハッシュ保存する設計は、**実装できなかった** | **保存方式を決める前に、使う側のフローを確認する** |
| swap / core dump / kdump が考慮されていなかった | **メモリ上の秘密はディスクに漏れる経路がある** |
| **同じ経路がアプリサーバーにも存在することを見落としていた** | **ある場所で見つけた問題は、他の場所にもないか確認する** |
| `Cache-Control: no-store` による bfcache 対策は、**2025 年の Chrome の変更で無効になっていた** | **ブラウザ挙動の知識は古くなる。実機で確認する** |
| **`location.reload()` は POST 結果ページで再送確認ダイアログを招き、キャンセルされると平文が残る** | **対策が動く文脈まで確認する** |
| SQLite の PRAGMA は接続単位で、起動時 1 回では全接続に効かない | **「設定した」と「効いている」は違う。テストで確認する** |
| 監査の fail closed を seal に適用すると、DEK を消せなくなる | **セキュリティを上げる操作まで止めてはならない** |
| **同じ誤りが `machine.disable` / `grant.delete` にも残っていた** | **原則を立てたら、全ての適用箇所を点検する** |
| 型付き allowlist にしても、User-Agent は攻撃者制御の文字列だった | **型はフィールド名を制限するだけ。値の安全性は別問題** |
| **C6(トークン発行と seal の競合)を塞いだが、同型の競合が revoke 系に残っていた** | **競合を 1 つ見つけたら、同じ構造が他にないか探す** |

**最も重要な教訓:**

> このシステムで最初に壊れるのは暗号実装ではなく、
> 認証・ネットワーク境界・並行制御・運用手順の噛み合わせである。

---

## 絶対に守るルール

以下に違反する実装は、動作しても却下される。

### 暗号

1. **暗号アルゴリズムを自作しない**
2. **`math/rand` を暗号用途で使わない。** 鍵、nonce、トークン、セッション ID は
   全て `crypto/rand`
3. **nonce を再利用しない**
4. **生の秘密、および検証用 digest の直接比較は
   `crypto/subtle.ConstantTimeCompare` を使う。**
   ただし、**暗号学的ハッシュを map / DB の lookup key に使うのは別問題であり、
   これには適用されない**(`map[[32]byte]` の lookup、`WHERE token_hash = ?` 等)。
   lookup で候補を絞った後、秘密そのものの比較には ConstantTimeCompare を使う
5. **独自プロトコルを実装しない**
6. **AAD は固定幅バイナリで構築する。** 型変換(int64 → uint32)は
   範囲を検査し、範囲外はエラーにする
7. **argon2 は低エントロピーな秘密(人間のパスワード、MK)にのみ使う。**
   **未認証で高頻度に呼べる経路(Machine API の認証)で argon2 を使わない。**
   `client_secret` やトークンは `crypto/rand` 由来の高エントロピー値なので
   SHA-256 で十分であり、argon2 は DoS 増幅器にしかならない。
   **Web UI のログイン / unseal は VPN 内からのみ到達可能かつ semaphore で
   制限されるため、argon2 を使ってよい**
8. **`client_secret` はサーバーが `crypto/rand` で生成したものに限る。**
   **ユーザーによる指定・インポートを許す API / 画面を実装してはならない。**
   これはルール 7 が成立するための不変条件である

### マスターキーの取り扱い

9. **MK をコマンドライン引数から受け取らない**(`ps` で見える)
10. **MK を環境変数から受け取らない**(`/proc/<pid>/environ` に残る)
11. **MK をディスクに書かない**
12. MK は **stdin または HTTP リクエストボディからのみ** 受け取る
13. **MK の入力は「末尾の単一改行のみ除去 → 厳密な base64url →
    32 バイト確認」の順で正規化・検証する。** 前後の空白を trim しない
14. **unseal 後に MK と KEK をゼロクリアする。** unsealed 中に保持するのは DEK のみ
15. 使用後のバッファはゼロクリアする(best effort であることを認識した上で)
16. **ドキュメントに `echo -n "$KEY" | ...` を書かない。**
    `op read '...' | ssh vps 'sudo -n hokora unseal --stdin'` の形を使う
17. **ドキュメントで `sudo` を使う際は `-n` を付ける。**
    sudo がパスワードを要求すると stdin から MK を消費する
18. **`hokora rotate-master` は新 MK を生成しない。**
    生成は `hokora gen-key`(DB に触らない)。
    「生成 → DB 更新 → 1Password 保存前にクラッシュ」で全データが
    復旧不能になる事故を防ぐため

### ログ・エラー

19. **secret の値をログに出力しない**
20. **エラーメッセージに secret の値を含めない**
21. **認証エラーで情報を漏らさない。** 存在しない client_id / username でも
    dummy hash 計算を行う

### 監査

22. **secret へのアクセスは全て監査ログに記録する。** read も、失敗も
23. **bulk fetch は key ごとに 1 レコード、1 トランザクションで N 行 INSERT**
24. **監査ログには immutable ID を記録する。**
    slug / key は再利用可能なので、`target` 文字列だけでは追跡できない
25. **`actor` / `target` / `detail` に、攻撃者が制御できる生の入力を入れない。**
    存在しない client_id / username での認証失敗は `actor = "anonymous"` とし、
    相関が必要なら `detail.subject_digest`(`hex(SHA-256(input)[:8])`)を使う。
    **User-Agent は記録しない。**
    型付き allowlist はフィールド名を制限するだけで、値の安全性を保証しない
26. **fail closed は「セキュリティを下げる操作」のみ:**
    - secret の読み取り・書き込み・削除
    - unseal
    - 認証(成功・失敗とも。監査 DB 障害時も必ず拒否)
    - 各種 create
    - `master.rotate`
27. **fail open は「セキュリティを上げる操作」:**
    - **`seal`**
    - **`machine.disable` / `user.disable` / `grant.delete`**
    - **`machine.rotate_secret` / `user.password_change`**
    - **token / session の失効**
    - **logout**
    **緊急遮断操作を監査障害で止めてはならない。**
    fail open の意味は「本体の処理が成功したのに監査 INSERT だけが失敗した場合、
    本体を rollback しない」であり、「DB 更新失敗を無視する」ではない。
    監査の失敗は非機密の運用ログに出す
28. **監査ログの削除機能を実装しない**

### ネットワーク境界

29. **Machine API・Web UI・Admin socket に、それぞれ独立した `ServeMux` を渡す**
30. **Web UI の bind address のデフォルトは `127.0.0.1`。**
    `0.0.0.0` を指定されたら警告ログを出す
31. **`InsecureSkipVerify` 相当のオプションを実装しない**
32. **IP allowlist をアプリ層で実装しない**(firewalld の責務)
33. **`/healthz` はバージョン文字列を返さない**
34. **TLS のリロードに失敗したら、古い有効な証明書を維持する。**
    証明書と秘密鍵は versioned directory + symlink でペア単位に切り替える

### リソース制限

35. **レート制限の第一段は送信元 IP**
36. **プロセス内の map には上限と TTL を設ける**
37. **HTTP サーバーの timeout を全て設定する**(ゼロは無制限)
38. **`http.MaxBytesReader` を全ての listener で使う**
39. **argon2 の同時実行数を semaphore で制限する**

### Web UI

40. **`template.HTML` / `template.JS` / `template.URL` を使わない**
41. **一覧 API / 画面で平文を返さない。** マスクは表示上の話ではなく、
    **サーバーが値を返さない**こと
42. **CDN から何も読み込まない**(CSP `default-src 'self'`)
43. **レスポンス圧縮を有効にしない。** CSRF トークンが全ページに埋まるため、
    圧縮 + 反射文字列は理論上 BREACH の対象になる
44. Cookie は `__Host-` prefix + `HttpOnly` + `Secure` + `SameSite=Strict`、
    `Domain` 属性なし
45. **ログイン成功時にセッション ID を再生成する**
46. **セッショントークンは SHA-256 ハッシュで DB 保存する**
47. **CSRF トークンは DB に保存しない。セッショントークンから導出する**
    (`SHA-256("hokora/csrf/v1" || rawSessionToken)`)。
    ハッシュ保存はフォーム描画時に埋め込む生値がなく、実装できない
48. **ログイン POST は Fetch Metadata / Origin で保護する。**
    Origin は **scheme / host / port の完全一致**を検証し、`Origin: null` は拒否。
    両方が欠けていたら拒否
49. **`Cache-Control: no-store` だけでは bfcache を防げない。**
    `static/bfcache.js` で `pageshow` の `persisted` を検出する。
    **平文ページ(`data-bfcache="replace"`)は、DOM を消してから
    `location.replace()` で安全な GET URL へ退避する。**
    **`location.reload()` は POST 結果ページで再送確認を招くため使わない。**
    通常のページは `reload` でよい。
    **これは「JS は原則不要」の明示的な例外。** CSP を維持するため
    インラインにしない
50. **平文を含むページは reveal だけではない。**
    Machine 作成時と credential 再発行時の credential 表示も対象

### 認可・期限

51. **トークンは認証の証明であり、認可の証明ではない。**
    各リクエストで machine の `disabled`、grant、**祖先の `deleted_at`**、
    **トークンの有効期限**を再検査する
52. **期限判定を sweep に依存しない。** sweep はメモリ / DB の掃除であって、
    認証上の期限判定ではない。`Lookup()` で必ず期限を検査する。
    セッションは絶対期限と idle 期限の両方を各リクエストで検査する
53. **credential 再発行・無効化時に、当該 machine の全トークンを削除する。**
    **パスワード変更・ユーザー無効化時に、当該ユーザーの全セッションを削除する**
54. **論理削除された project / environment へのアクセスは、
    grant がない場合と同じく 403 を返す。** 区別すると存在情報を漏らす

### データ

55. **`item_versions` を通常の操作系から UPDATE しない。** 追記のみ。
    **例外は `hokora rotate-dek`(Phase 3)のみ**
56. **grant と session を除き、物理削除を実装しない。**
    - project / environment / item: `deleted_at`
    - **user / machine: `disabled`**(`deleted_at` を持たない)
    - **grant / session: 物理 DELETE を許可**(例外)
57. **外部キーは全て `ON DELETE RESTRICT`。** CASCADE を使わない。
    **`audit_logs` は FK を持たない**
58. **すべての取得クエリで、全祖先の `deleted_at IS NULL` を検査する。**
    project を論理削除しても配下の environment / item は残るため、
    これを怠ると削除した project の secret が取得可能になる
59. **SQLite の PRAGMA は DSN で全接続に適用する。**
    `foreign_keys` はデフォルト OFF かつ接続単位。起動時に 1 接続で
    実行しても、後からプールが開いた接続や再生成された接続では無効になる。
    **`SetMaxOpenConns(1)` だけでは不十分**(その接続に PRAGMA を適用する
    必要があり、接続は再生成されうる)
60. **secret 値は「有効な UTF-8、NUL バイトなし、64 KB 以下」を
    サーバー側で検証する**

### 並行制御

61. **`Seal()` は進行中の暗号操作の完了を待つ**(write lock)
62. **`Seal()` 時に machine token store を空にする**
63. **トークン発行処理全体(unsealed 確認 → 検証 → store への追加)を
    read lock 内で完結させる**(C6)
64. **`machine.rotate_secret` / `machine.disable` の
    「DB 更新 → トークン削除」を write lock 内で実行する**(C8)。
    **これは C6 と同型の競合である。** 塞がないと、旧 credential で作られた
    トークンが rotate 完了後に 15 分生き残る
65. **ログイン処理は、セッション INSERT と同一トランザクション内で
    `password_hash` を再読し、検証に使った値と一致することを確認する**(C9)。
    **argon2 の数百 ms が競合ウィンドウになる**
66. **`rotate-master` 全体を専用 mutex で直列化する**(C10)
67. **ロックの取得順序を固定する: Vault.mu → tokenStore.mu**
68. **`go test -race` は意味上の競合を検出しない。**
    C6 / C8 / C9 / C10 のテストを明示的に書くこと
69. **`mlockall` に失敗したら起動を中止する**(`LimitMEMLOCK=infinity` が必要)

---

## 実装しないもの(スコープ厳守)

実装したくなったら、まず THREAT_MODEL.md の改訂を提案すること。

- マルチテナント / 複数組織
- Secret の自動ローテーション
- 外部サービス連携 / PKI / SSH キー管理 / Dynamic secrets / Honey tokens
- SSO / OIDC / SPA フロントエンド
- 冗長化 / クラスタリング
- MySQL / PostgreSQL 対応 / Redis
- クライアント側キャッシュ
- **`hokora export`(`.env` 出力)**
- **item のコメント / メモ欄**
- **viewer ロール**(admin 単一)
- **TLS 証明書の自動取得**(certbot、**別ホスト**に任せる)
- **Machine API の version パラメータ**
- **物理削除**(grant / session を除く)
- **IP allowlist 機能**(firewalld の責務)
- **`AuditDetail.UserAgent`**
- **レスポンス圧縮**

---

## 技術スタック

| 項目 | 選択 | 備考 |
|------|------|------|
| 言語 | Go 1.26.5+ | `go.mod` が正。**最低バージョンは「既知の到達可能な脆弱性が無い最新の安定版」に合わせる。** CI は `go-version-file: go.mod` でこの版を入れるため、宣言が古いと CI は古い(脆弱な)処理系で走り続ける |
| DB | SQLite | `modernc.org/sqlite`(CGO 不要) |
| DB アクセス | `database/sql` + 素の SQL | **ORM を使わない** |
| HTTP | `net/http` + `http.ServeMux` | **Web フレームワークを使わない** |
| テンプレート | `html/template` | |
| 暗号 | 標準ライブラリ + `golang.org/x/crypto` | |
| syscall | `golang.org/x/sys/unix` | **mlockall のみ**(DESIGN §4.2) |
| アセット同梱 | `embed` | |

**依存の追加は原則禁止。**

許可されている外部依存:
- `modernc.org/sqlite`
- `golang.org/x/crypto`(argon2)
- `golang.org/x/sys`(mlockall)

**SDK(`sdk/`)は標準ライブラリのみ**(Phase 2 の `WithMlockall()` を除く)。

### ツール依存(`go.mod` の `tool` ディレクティブ)

上記の禁止は **バイナリにリンクされる依存** の話である。開発ツールは
`tool` ディレクティブで宣言し、バージョンを `go.mod` で固定する:

- `github.com/golangci/golangci-lint/v2/cmd/golangci-lint`
- `golang.org/x/vuln/cmd/govulncheck`

これらは `go build` の成果物には入らない。`go.mod` / `go.sum` に大量の
indirect が並ぶのはこのためであり、**本体の依存が増えたわけではない**。
成果物に入る依存かどうかは `go list -deps .` で確認できる。

ツール依存を足すときも、**用途を説明できるものに限る**。

---

## リポジトリ構成

```
hokora/
├── main.go              # サブコマンドのディスパッチのみ
├── cmd_*.go
├── crypto.go            # KDF、AEAD、itemAAD、MK 正規化、ゼロクリア
├── keyring.go           # MK/KEK/DEK、seal/unseal、並行制御(C1-C10)
├── mlock.go             # mlockall
├── store.go             # SQLite。DSN での PRAGMA 適用
├── schema.sql           # embed
├── migrate.go           # PRAGMA user_version
├── model.go             # 構造体、バリデーション
├── audit.go             # action allowlist、AuditDetail、fail open/closed
├── token.go             # tokenStore
├── server.go            # 3 つの mux、2 つの listener、TLS リロード
├── api.go / admin.go / auth.go / session.go / ratelimit.go / ui.go
├── templates/           # embed
├── static/              # style.css, bfcache.js
├── sdk/                 # 外部から import される Go SDK
└── docs/
```

**パッケージは `main` と `sdk` の 2 つのみ。** `internal/` を作らない。

---

## コーディング規約

- `gofmt` / `goimports` は必須。`golangci-lint` を通すこと
- エラーは握りつぶさない。`_ = err` は禁止
- エラーは `fmt.Errorf("...: %w", err)` でラップする
- コメントは日本語で書いてよい。ただし **`sdk/` の godoc は英語**
- 暗号の AEAD 操作は `sealBytes` / `openBytes`、
  サーバー状態の操作は `Seal()` / `Unseal()`。混同しないこと

### テスト

- **テストは実装と同時に書く**
- `go test -race` を常に通す
- テーブル駆動テストを使う。`t.Helper()` を付ける
- 暗号レイヤーは特に手厚く(ラウンドトリップ、誤鍵、誤 AAD、nonce、境界値)
- **並行制御は race detector では足りない**(ルール 68)
- **「設定した」ではなく「効いている」をテストする**(PRAGMA、mux 分離)
- **ブラウザ挙動に依存する対策は実機で確認する**(bfcache)

### godoc(sdk/ のみ)

- **嘘をつかない。** `Zero()` が best effort ならそう書く
- **防御範囲を過大に書かない。** swap / core dump / secret zero problem に
  ついても明記し、脅威モデルへの参照を含める

---

## 作業の進め方

`docs/ROADMAP.md` に従う。**マイルストーンを飛ばさない。**

M1(基盤) → M2(暗号)→ **M3(seal/unseal・監査コア・トークン基盤)** →
**M4(認証・境界)** → **M5(Web UI)** → M6(クライアント・Runbook)→
M7(リリース準備)

**M4 と M5 が最重要。**

### コミット

- 意味のある単位でコミットする。コミットメッセージは日本語でよい
- **secret や鍵を含むファイルをコミットしない**(`.gitignore` を整備)

#### コミット前に必ず実行すること

**1 → 2 → 3 の順に、直列で実行する。** 2 と 3 を並走させない
(品質レビューがソースを直す一方でテスト作成が同じソースを読むため、
編集が競合する)。

1. **`make all`**(`fmt-check` → `vet` → `lint` → `test` → `build`)を通す。
   `.github/workflows/ci.yml` と同じ内容なので、ここで落ちるものは push
   しても落ちる。**依存を足した / 更新したときは `make vuln` も回す**
   (脆弱性検査は `vuln.yml` に分離してあり、`make all` には含まれない)
2. **コード品質レビュー**を変更差分に対して実行し、指摘を反映する。
   Claude Code なら `/simplify` スキル。他のエージェントでも、
   再利用性・簡潔性・効率・実装の深さを見る同等の工程であればよい
3. **テスト作成を別エージェントに委ねる。** 「テストを書く担当」として
   独立したエージェントを起動し、**2 の修正後のソースを前提に**
   テストの追加・修正をさせる(Claude Code なら Agent tool で
   `test-writer` 相当のサブエージェント)。実装した本人とは別の視点で
   カバレッジの穴を埋めるための工程である。追加されたテストを取り込んだら、
   **1 をもう一度通してから** commit する

**2 と 3 を省略しない。** このリポジトリで最初に壊れるのは暗号実装ではなく、
認証・境界・並行制御・運用手順の噛み合わせである(冒頭の教訓)。
噛み合わせの綻びは単体のテストを通り抜けるため、差分全体を読み直す工程と、
書いた本人以外がテストを足す工程を機械的に挟む。

なお、**3 は「テストは実装と同時に書く」の代わりではない**。実装時に自分で
テストを書いたうえで、コミット前にもう一度別の目で穴を探す、という順序である。

lint の指摘は原則として**実装側を直して解消する**。`//nolint` で抑制するのは、
抑制する理由をコメントで説明できる場合に限る。

---

## 未解決の設計課題

勝手に決めないこと。

| # | 課題 | いつ |
|---|------|------|
| Q5 | MVP でのバックアップ手順の詳細 | **M6 で決める** |
| Q6 | Web UI の DNS レコード設計 | **M6 で決める** |

確定済み: Q1(TLS、certbot は別ホスト)、**Q2(slug / key の文字種。M1 で確定。
DESIGN §14)**、Q3(初期 admin パスワード)、Q4(監査ログ保持期間)

---

## 質問すべきとき

- THREAT_MODEL.md に根拠のない機能を実装したくなったとき
- 「絶対に守るルール」に反する必要が生じたとき
- 新しい外部依存を追加したくなったとき
- 暗号設計を変更したくなったとき
- **防御の主張を書きたくなったとき**(その仕組みが実際にどう動くか確認する)
- **ブラウザや OS の挙動に依存する対策を書くとき**(知識が古い可能性がある)
- **並行処理を書くとき**(C6 / C8 / C9 / C10 と同型の競合を作っていないか)
- 上記の未解決課題に触れるとき

**動くものを早く作るより、正しいものを作ることを優先する。**
これは秘匿情報を扱うプロダクトである。
