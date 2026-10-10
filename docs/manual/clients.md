# アプリから secret を取得する

アプリは、マシンの credential で hokora に認証し、アクセス権のある環境の secret を受け取ります。
このページは、取得の方法の選び方と、credential の置き方をまとめます。

マシンの作成とアクセス権の割り当ては [Web UI の使い方](web-ui.md) を見てください。

## 取得の方法を選ぶ

| 方法 | 向いている用途 | secret の行き先 |
|---|---|---|
| Go SDK | Go のアプリ。使えるならこれを選びます | プロセスのメモリ（`[]byte`） |
| `hokora-client bulk` | SDK を組み込めないアプリの設定ファイル（Perl、PHP など） | 標準出力の JSON を、読み手がパイプで受ける |
| `hokora-client get` | 人が端末で 1 個の値を確かめる | 標準出力 |
| `hokora-client run` | 環境変数で secret を受け取る既存のアプリの移行 | 子プロセスの環境変数 |

どの方法でも、次のことは変わりません。

- **アプリと同じ OS ユーザーの権限を取った攻撃者は、同じ secret を取得できます。**
  credential を読めるからです。
  取得の方法を変えても、この点は防げません
- 値はどこにもキャッシュされません。
  呼び出すたびに、認証と取得の通信をします
- TLS の検証を無効にする設定はありません

## credential を置く

アプリサーバーに、次の 5 行のファイルを置きます。
`HOKORA_CLIENT_ID` と `HOKORA_CLIENT_SECRET` は、Web UI でマシンを作成または再発行したときに表示された値です。

```bash
# /etc/hokora/credentials (0600, root:root)
HOKORA_ADDR=https://hokora.example.com:9443
HOKORA_CLIENT_ID=...
HOKORA_CLIENT_SECRET=...
HOKORA_PROJECT=myapp
HOKORA_ENV=prod
```

| 項目 | 内容 |
|---|---|
| `HOKORA_ADDR` | Machine API の URL。ポートの既定は 9443 です |
| `HOKORA_CLIENT_ID` / `HOKORA_CLIENT_SECRET` | マシンの credential |
| `HOKORA_PROJECT` / `HOKORA_ENV` | 取得する環境。プロジェクトと環境の slug を書きます |

- **ファイルの権限は 0600 にします。0644 にしないでください**
- 1 つのマシンに複数の環境のアクセス権があっても、1 回の取得で読むのは `HOKORA_PROJECT` と `HOKORA_ENV` で指定した 1 つの環境です

### systemd のサービスに渡す

systemd で動かすアプリには、`LoadCredential=` で渡します。
SDK は、展開先の `$CREDENTIALS_DIRECTORY/hokora` を読みます。

```ini
[Service]
ExecStart=/usr/local/bin/myapp
User=myapp
LoadCredential=hokora:/etc/hokora/credentials
PrivateMounts=true
LimitCORE=0
```

`LoadCredential=` で展開したファイルは、サービスの実行ユーザーから読めます。
アプリのユーザーの権限を取った攻撃者から credential を隠す仕組みではありません。

### 設定の解決の順序

設定は、次の順で探します。
先に見つかった値を使います。

1. コードやフラグでの指定。SDK では `WithAddress` など、`hokora-client` では `--addr` などです
2. credential ファイル
3. 環境変数。`HOKORA_ADDR`、`HOKORA_CLIENT_ID`、`HOKORA_CLIENT_SECRET`、`HOKORA_PROJECT`、`HOKORA_ENV` です

credential ファイルの場所は、SDK と `hokora-client` で既定が違います。

| | 既定のファイル | 変え方 |
|---|---|---|
| SDK | `$CREDENTIALS_DIRECTORY/hokora`（`LoadCredential=` の展開先） | `WithCredentialsFile` |
| `hokora-client` | `/etc/hokora/credentials` | `--credentials` |

## Go SDK

```
go get github.com/kan/hokora/sdk
```

SDK は独立した module で、標準ライブラリだけに依存します。
Go 1.24 以降で使えます。

```go
import hokora "github.com/kan/hokora/sdk"

client, err := hokora.New()          // $CREDENTIALS_DIRECTORY/hokora から設定を読む
if err != nil { /* ... */ }

secrets, err := client.Fetch(ctx)    // 環境の secret を全て取得する
if err != nil { /* ... */ }
defer secrets.Zero()

dsn, ok := secrets.Get("DATABASE_URL")   // []byte
```

| 呼び出し | 内容 |
|---|---|
| `client.Fetch(ctx)` | 環境の secret を全て取得します。監査ログには key ごとに 1 行が残ります |
| `client.FetchKey(ctx, key)` | 1 個の key だけを取得します。監査ログに残るのもその 1 行です |
| `secrets.Get(key)` | 値を `[]byte` で返します |
| `secrets.GetString(key)` / `MustGetString(key)` | 値を `string` で返します |
| `secrets.Zero()` | 保持している `[]byte` をゼロで埋めます |

- **`Fetch` と `FetchKey` は、呼ぶたびに認証します。**
  起動時に 1 回取得し、その値をプロセスの中で使い回す形にしてください。
  リクエストごとに呼ぶと、認証のレート制限に当たります
- `Zero()` で消せるのは、SDK が持っている `[]byte` だけです。
  `GetString` で取り出した `string` は消せません。
  swap や core dump でメモリがディスクに出る経路も防げません
- 存在しない key を `FetchKey` で指定すると、アクセス権が無い場合と同じ `ErrForbidden` になります。
  サーバーは、どの key があるかを区別して返しません

エラーは `errors.Is` で見分けられます。

| エラー | 意味 |
|---|---|
| `ErrMissingConfig` | 設定が足りません。メッセージに足りない項目が出ます |
| `ErrUnauthorized` | credential が違うか、マシンが無効化されています |
| `ErrForbidden` | アクセス権が無いか、プロジェクトや環境、key がありません |
| `ErrSealed` | サーバーが sealed です |

API の全体は [pkg.go.dev](https://pkg.go.dev/github.com/kan/hokora/sdk) にあります。

## hokora-client

`hokora-client` は、アプリサーバーに置く取得専用のコマンドです。
サーバー本体の `hokora` を、アプリサーバーに置く必要はありません。

credential ファイルは root だけが読めるので、端末から使うときは `sudo` を付けます。

### `get` で 1 個の値を端末で確かめる

```bash
sudo hokora-client get DATABASE_URL
```

値を 1 行、標準出力に出します。
読むのは指定した 1 個の key だけで、監査ログに残るのもその 1 行です。

端末での確認のためのコマンドです。
`hokora-client get KEY > file` のように、ファイルを作る用途には使わないでください。

### `bulk` を設定ファイルからパイプで読む

```bash
sudo hokora-client bulk
# {"API_TOKEN":"...","DATABASE_URL":"..."}
```

環境の secret を全て、1 個の JSON オブジェクトとして標準出力に出します。

- key は昇順に並びます。
  secret が 0 件なら `{}` を出します
- **失敗したときは、標準出力に何も出さず、0 以外の終了コードで終わります。**
  読み手は、必ず終了コードを確かめてください。
  確かめないと、空の設定のままアプリが起動します
- 出力をファイルに保存しないでください。
  パイプで受け取り、ディスクに書かない形で使います
- 呼ぶたびに、環境の全ての key が読まれたと監査ログに記録されます

Perl の設定ファイルから読む例は [運用 Runbook](../OPERATIONS.md) の §8.4 にあります。

### `run` で環境変数に入れて起動する

```bash
sudo hokora-client run -- /usr/local/bin/legacy-app --flag
```

環境の secret を、key を名前とする環境変数に入れて、`--` の後ろのコマンドを起動します。
終了コードは、起動したコマンドのものをそのまま返します。

**環境変数は `/proc/<pid>/environ` から読めます。**
アプリと同じ OS ユーザーの権限を取った攻撃者は、credential を使わなくても secret の値をそこから読めます。
`run` は、環境変数で secret を受け取る既存のアプリを移行するための手段です。
Go のアプリでは SDK を使ってください。

### 共通のフラグ

| フラグ | 内容 |
|---|---|
| `--credentials <path>` | credential ファイルの場所（既定は `/etc/hokora/credentials`） |
| `--addr <url>` | `HOKORA_ADDR` を上書きします |
| `--project <slug>` / `--env <slug>` | `HOKORA_PROJECT` / `HOKORA_ENV` を上書きします |
| `--ca <pem>` | 内部 CA の証明書。指定すると、その CA だけを信頼します。公的 CA の証明書を使う通常の構成では要りません |

フラグは、`get` の key や `run` の `--` より前に書きます。

```bash
sudo hokora-client get --credentials /etc/hokora/credentials-batch DATABASE_URL
```

## 認証の回数の上限

認証には、1 分あたりの上限があります。
成功した認証も数えます。

| 数える単位 | 上限 |
|---|---|
| 送信元の IP アドレス | 30 回 / 分（変えられません） |
| credential | 10 回 / 分（既定。マシンごとに 30 回まで上げられます） |

SDK と `hokora-client` は、どちらも取得のたびに 1 回認証します。
上限に当たるのは、cron から短い間隔で `hokora-client` を起動する構成や、リクエストごとに `Fetch` を呼ぶ構成です。

上限を超えた呼び出しは `rate limited` のエラーになります。
SDK と `hokora-client` は、自動では再試行しません。
60 秒待てば、上限に対する回数の数え直しが始まっています。

上限の上げ方と値の決め方は、[運用 Runbook](../OPERATIONS.md) の §8.7 にあります。

## うまく取得できないとき

| エラー | 見るところ |
|---|---|
| `missing configuration` | credential ファイルの場所と、5 つの項目が揃っているか |
| `invalid credentials`（401） | credential が再発行されていないか、マシンが無効化されていないか。意図したファイルを読んでいるか |
| `forbidden`（403） | アクセス権があるか。`HOKORA_PROJECT` と `HOKORA_ENV` が合っているか。プロジェクトや環境が削除されていないか |
| `server is sealed`（503） | サーバーが sealed です。unseal します |
| `rate limited`（429） | 認証の回数の上限に当たっています |

削除されたプロジェクトや環境、存在しない key は、アクセス権が無い場合と同じ `forbidden` になります。
サーバーは、理由を区別して返しません。
