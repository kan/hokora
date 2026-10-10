# コマンド一覧

hokora には 2 つのバイナリがあります。

| バイナリ | 置く場所 | 用途 |
|---|---|---|
| `hokora` | hokora のサーバー | サーバーの起動と管理 |
| `hokora-client` | アプリサーバー | secret の取得 |

このページは、サブコマンドとフラグの早見表です。
手順と注意は [運用 Runbook](../OPERATIONS.md) に書いてあります。
実行する前に、該当する節を読んでください。

## hokora（サーバー）

| コマンド | 内容 | サーバーの稼働 | Runbook |
|---|---|---|---|
| `hokora init` | DB を初期化する。更新時はスキーマを移行する | 停止中に実行 | §1.1、§1.3 |
| `hokora serve` | サーバーを起動する（sealed で起動する） | | §2 |
| `hokora unseal --stdin` | マスターキーを渡して unseal する | 稼働中 | §3 |
| `hokora seal` | seal する | 稼働中 | §3 |
| `hokora status` | サーバーの状態を表示する | 稼働中 | §3 |
| `hokora gen-key` | 新しいマスターキーを生成して表示する | どちらでも | §10 |
| `hokora rotate-master --stdin` | マスターキーを替える | 稼働中 | §10 |
| `hokora backup --out <path>` | 暗号文のバックアップを書き出す | どちらでも | §9 |
| `hokora audit-prune --keep-days <N>` | 古い監査ログを刈り込む | どちらでも | §12.3 |

### マスターキーの渡し方

**マスターキーは、標準入力からだけ受け取ります。**
コマンドライン引数や環境変数では渡せません（`ps` や `/proc` から見えてしまうためです）。

パスワードマネージャから読み出し、SSH 越しにそのまま標準入力へつなぎます。

```bash
op read 'op://Infra/hokora/master-key' | ssh vps 'sudo -n hokora unseal --stdin'
```

- **`sudo` には `-n` を付けます。**
  `sudo` がパスワードを聞くと、標準入力からマスターキーを 1 行読み取ってしまいます。
  `-n` を付けると、パスワードが必要な場合はすぐに失敗します。
  sudoers の設定は Runbook の §3.1 にあります
- マスターキーを変数に入れて `echo` で渡す形は使わないでください。
  シェルの履歴や引数にマスターキーが残ります

### `hokora init`

```bash
sudo -u hokora hokora init --db /var/lib/hokora/hokora.db
```

新しい DB を作り、次の 2 つを 1 回だけ出力します。
後から表示し直すことはできません。

| 出力先 | 内容 |
|---|---|
| 標準出力 | マスターキー |
| 標準エラー出力 | 初期 admin のユーザー名とパスワード |

| フラグ | 内容 |
|---|---|
| `--db <path>` | DB ファイルの場所（既定は `/var/lib/hokora/hokora.db`） |
| `--migrate-only` | 既にある DB のスキーマを移行するだけにする。ファイルが無ければエラーで終わる |

既にある DB に対しては、未適用のスキーマの移行だけを行います。
このとき、マスターキーとパスワードは出力しません。

**バイナリを更新するときは、必ず `--migrate-only` を付けます。**
付けないと、`--db` を打ち間違えたときに、その場所へ空の DB が作られます。

### `hokora serve`

```bash
hokora serve --ui-addr <VPN の IF の IP>:8443
```

通常は systemd から起動します。
起動直後は sealed です。

| フラグ | 既定値 | 内容 |
|---|---|---|
| `--db <path>` | `/var/lib/hokora/hokora.db` | DB ファイルの場所 |
| `--machine-addr <addr>` | `0.0.0.0:9443` | Machine API の待ち受けアドレス |
| `--ui-addr <addr>` | `127.0.0.1:8443` | Web UI の待ち受けアドレス。VPN の IF に向けます |
| `--admin-socket <path>` | `/run/hokora/admin.sock` | admin socket の場所 |
| `--tls-dir <path>` | `/var/lib/hokora/tls/current` | `cert.pem` と `key.pem` を置くディレクトリ |

- メモリをロックできないと（`LimitMEMLOCK=infinity` が無いと）、起動を中止します
- スキーマのバージョンが合わない DB は開きません。
  `hokora init --migrate-only` で移行します
- `SIGHUP` を送ると、TLS の証明書を読み直します。
  読み直しに失敗したときは、それまでの証明書のまま動き続けます

### `hokora unseal --stdin` / `seal` / `status`

```bash
op read 'op://Infra/hokora/master-key' | ssh vps 'sudo -n hokora unseal --stdin'
ssh vps 'sudo -n hokora seal'
ssh vps 'sudo -n hokora status'
```

| フラグ | 内容 |
|---|---|
| `--socket <path>` | admin socket の場所（既定は `/run/hokora/admin.sock`） |
| `--stdin` | `unseal` で必須（`seal` と `status` には付けません）。マスターキーを標準入力から読むことを明示します |

- `seal` は、復号用の鍵をメモリから消し、発行済みのトークンを全て無効にします。
  以後、unseal するまで secret は取得できません。
  緊急の遮断に使えます
- `status` は `state=unsealed` のように状態を表示します。
  secret の内容は表示しません
- unseal は Web UI からもできます。
  seal はコマンドだけです

### `hokora gen-key` / `rotate-master --stdin`

マスターキーを替えるときに使います。
**順序を間違えると、全ての secret が復号できなくなります。**
必ず Runbook の §10 の手順で行ってください。

- `gen-key` は新しいマスターキーを標準出力に出すだけで、DB には触りません
- `rotate-master --stdin` は、現在のマスターキーと新しいマスターキーを、標準入力から 2 行で受け取ります（`--stdin` は必須です）。
  新しいマスターキーを生成することはありません
- 新しいマスターキーをパスワードマネージャに保存できたことを確かめてから、`rotate-master` を実行します

### `hokora backup`

```bash
ssh vps "sudo -n hokora backup --out /var/lib/hokora/backups/hokora-$(date +%Y%m%d-%H%M%S).db"
```

| フラグ | 内容 |
|---|---|
| `--out <path>` | 書き出し先（必須）。既にあるファイルは上書きしません |
| `--db <path>` | DB ファイルの場所 |

- サーバーを止めずに実行できます。
  sealed でも取れます
- バックアップに入るのは暗号文だけで、マスターキーは入りません。
  **復元には、バックアップと、その時点のマスターキーの両方が要ります**
- 暗号文でも、全ての secret が入っています。
  DB 本体と同じ扱いで保管し、マスターキーとは別の場所に置きます
- バックアップがあることと、復元できることは別です。
  復元の試験は Runbook の §9.2 にあります

### `hokora audit-prune`

```bash
ssh vps 'sudo -n -u hokora hokora audit-prune --keep-days 180 --dry-run'
ssh vps 'sudo -n -u hokora hokora audit-prune --keep-days 180'
```

| フラグ | 内容 |
|---|---|
| `--keep-days <N>` | 残す日数（必須）。30 以上を指定します |
| `--dry-run` | 消える行数を数えるだけで、何も変えません |
| `--db <path>` | DB ファイルの場所 |

- 消えるのは、指定した日数より古い「マシンの読み取りの成功」と「マシンの認証の成功」の行だけです。
  失敗の行、人の操作の行、刈り込み自体の記録は残ります
- 既定値はありません。
  どこまで残すかは、運用する人が決めます。
  刈り込んだ期間については、その secret が読まれたかどうかを後から確かめられなくなります
- サーバーを止めずに実行できます
- `hokora` ユーザーで実行します（`sudo -n -u hokora`）

## hokora-client（アプリサーバー）

| コマンド | 内容 |
|---|---|
| `hokora-client get <KEY>` | 1 個の値を標準出力に出す（端末での確認用） |
| `hokora-client bulk` | 環境の secret を全て、1 個の JSON オブジェクトで標準出力に出す |
| `hokora-client run -- <コマンド>` | secret を環境変数に入れて、コマンドを起動する（移行用） |

フラグと使い分けは [アプリから secret を取得する](clients.md) を見てください。

## 実装していないコマンド

次のものは、意図して用意していません。

| 無いもの | 理由 |
|---|---|
| secret を `.env` などのファイルに書き出すコマンド | secret をディスクに置かないことが hokora の目的だからです |
| 監査ログを Web UI や API から消す機能 | 消せるのは、サーバー上で実行する `audit-prune` だけです |
| TLS の検証を無効にするフラグ | 通信の相手を確かめられなくなるためです |
| `go install github.com/kan/hokora@version` でのインストール | リリースのバイナリを使うか、clone して `make build` でビルドします |
