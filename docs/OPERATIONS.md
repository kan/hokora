# OPERATIONS.md — hokora 運用 Runbook

本書は hokora を本番に投入し、運用するための手順書である。**初見の運用担当者
（開発者でなくてよい）が、この手順だけで unseal・バックアップ・復元まで実施
できる**ことを目標にする。

設計の根拠は必要に応じて `docs/DESIGN.md` / `docs/THREAT_MODEL.md` を参照する。
**hokora が守らないもの**（secret zero problem、アプリサーバーのディスク漏洩、
revoke の限界）を誤解しないよう、まず `docs/THREAT_MODEL.md` を読むこと。

---

## 0. 前提と既定値

| 項目 | 既定値 | 変更フラグ |
|------|--------|-----------|
| DB ファイル | `/var/lib/hokora/hokora.db` | `serve/init --db` |
| admin socket | `/run/hokora/admin.sock`（0600 hokora:hokora） | `serve --admin-socket` / `seal・status・unseal --socket` |
| Machine API bind | `0.0.0.0:9443` | `serve --machine-addr` |
| Web UI bind | `127.0.0.1:8443`（VPN の IF に寄せる） | `serve --ui-addr` |
| TLS ディレクトリ | `/var/lib/hokora/tls/current`（symlink） | `serve --tls-dir` |
| 実行ユーザー | `hokora`（非 root） | systemd unit |

- **サーバーは非 root で動く。** ただし `mlockall` のため
  `LimitMEMLOCK=infinity` が要る（§2）。
- **TLS 証明書ディレクトリには `cert.pem` と `key.pem` を置く。** 証明書取得は
  **別ホスト**の certbot が行う（§7）。
- クライアント側の credential は `/etc/hokora/credentials`（0600 root:root）。

---

## 1. 初期セットアップ

### 1.1 DB の初期化

```bash
sudo -u hokora hokora init --db /var/lib/hokora/hokora.db
```

`init` は次を **stdout / stderr に 1 回だけ** 出力する。**再表示はできない。**

- **マスターキー（MK）** … stdout。base64url。組織のパスワードマネージャに
  **今すぐ**保存する。hokora はディスクに書かず、二度と表示できない。
- **初期 admin ユーザー名と初期パスワード** … stderr。初回ログインで変更する。

MK は端末に残さないよう、保存経路を直結させる。例:

```bash
# stdout(MK)を 1Password に直接流し込む(端末履歴・画面に残さない)
sudo -u hokora hokora init | op document create --title 'hokora master-key'
```

> `echo -n "$KEY" | ...` の形は使わない（argv や履歴に MK が現れる）。

### 1.2 サーバー起動 → 初回ログイン → unseal

1. systemd で `hokora serve` を起動する（§2）。**起動直後は sealed** で、
   secret は出せない。
2. VPN 経由で Web UI（`https://<vpn-ip>:8443/ui/login`）に、初期 admin で
   ログインする。
3. **パスワード変更画面**に誘導される（`must_change_pw`）。新パスワードを設定。
   この画面は **sealed 状態でも動作する**。
4. Web UI の unseal 画面、または admin socket 経由（§3）で unseal する。
5. unseal 後、project / environment / item / machine / grant を作成する。

---

## 2. systemd unit

### 2.1 hokora 本体（`/etc/systemd/system/hokora.service`）

```ini
[Unit]
Description=hokora secret server
After=network-online.target
Wants=network-online.target

[Service]
User=hokora
Group=hokora
# --ui-addr を VPN の IF の IP に明示的に寄せる(既定は 127.0.0.1:8443 なので、
# そのままだと VPN 経由でログインできない。§1.2 の URL に到達させるため必須)。
# Machine API(:9443)は既定の 0.0.0.0 のままでよい(到達制限は firewalld。§4)。
ExecStart=/usr/local/bin/hokora serve --ui-addr <vpn-if-ip>:8443
# TLS 証明書をリロード(certbot deploy hook が symlink 切替後に送る)
ExecReload=/bin/kill -HUP $MAINPID

# --- THREAT_MODEL §5.3: メモリ内容をディスクに残さない ---
LimitCORE=0
LimitMEMLOCK=infinity          # mlockall に必須。不足すると起動が中止される

# --- ハードニング(DESIGN §4.3) ---
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

# DB を書ける唯一のパス。RuntimeDirectory で admin socket の親(0700)を作る
ReadWritePaths=/var/lib/hokora
RuntimeDirectory=hokora
RuntimeDirectoryMode=0700

[Install]
WantedBy=multi-user.target
```

- **`LimitMEMLOCK=infinity` が無いと `mlockall` に失敗し、hokora は起動を
  中止する**（`mlockall failed (LimitMEMLOCK=infinity is required)`）。
  これは仕様である。swap に鍵が出る状態で「動いてはいる」ことを許さない。
- **`LimitCORE=0`** で core dump にメモリ内容が出るのを防ぐ（§5 も参照）。

### 2.2 アプリケーションサーバー（`/etc/systemd/system/myapp.service`）

```ini
[Service]
ExecStart=/usr/local/bin/myapp
User=myapp
LoadCredential=hokora:/etc/hokora/credentials   # $CREDENTIALS_DIRECTORY/hokora へ展開
PrivateMounts=true          # THREAT_MODEL B7: 他サービスの credential dir を不可視化
LimitCORE=0                 # 推奨(THREAT_MODEL §5.4)。アプリ側も同じ経路で漏れる
```

- **アプリ側にも `LimitCORE=0` を推奨する。** 「hokora だけ守れば良い」ではない。
  secret を受け取ったアプリの core dump にも平文が出る（同じ経路が別の場所に
  ある）。
- SDK を使うアプリは `$CREDENTIALS_DIRECTORY/hokora` から credential を読む
  （§8）。

---

## 3. seal / unseal / status

admin socket 経由で MK を受け取る操作（`unseal` / `rotate-master`）は、**MK を
stdin からのみ受け取る**。`--stdin` を明示しないと拒否される（秘密の入力元を
明示させるため）。`seal` / `status` は MK を取らないので `--stdin` は不要。

```bash
# unseal(MK は 1Password から取り、SSH 越しに stdin へ。端末・argv に残さない)
op read 'op://Infra/hokora/master-key' | ssh vps 'sudo -n hokora unseal --stdin'

# seal(即時遮断。監査に書けなくても実行される = fail open)
ssh vps 'sudo -n hokora seal'

# 状態確認
ssh vps 'sudo -n hokora status'
```

### 3.1 sudoers（`sudo -n` 前提）

**`sudo -n`（非対話）を使う。** `sudo` がパスワードを要求すると、**stdin から
MK を 1 行消費してしまう**（DESIGN §10.1）。そのため hokora の admin コマンドは
NOPASSWD にする。

```
# /etc/sudoers.d/hokora
%hokora-admins ALL=(root) NOPASSWD: /usr/local/bin/hokora unseal --stdin, /usr/local/bin/hokora rotate-master --stdin, /usr/local/bin/hokora seal, /usr/local/bin/hokora status
```

- **`rotate-master --stdin` も NOPASSWD に含める**（§10 で `sudo -n` から呼ぶ）。
  含めないと `sudo -n` が即失敗し、rotate 手順が動かない。ここで慌てて `-n` を
  外すと、sudo のパスワードプロンプトが stdin の MK を食う（このセクションが
  防ごうとしている事故そのもの）。
- パスワードプロンプトが MK を食う事故を、`-n`（要求時は即失敗）と NOPASSWD の
  両方で防ぐ。

---

## 4. firewalld（Machine API の到達制限）

**IP allowlist は hokora ではなく firewalld の責務**（AGENTS.md ルール 32）。
Machine API（`:9443`）は `0.0.0.0` に bind するので、**到達可能な IP を
firewalld で絞る**。

```bash
# 既定ゾーンの :9443 をいったん閉じ、アプリサーバー IP からのみ許可する
sudo firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family=ipv4 source address=10.0.0.11/32 port port=9443 protocol=tcp accept'
sudo firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family=ipv4 port port=9443 protocol=tcp drop'
sudo firewall-cmd --reload
sudo firewall-cmd --list-rich-rules   # 反映確認
```

- Web UI（`:8443`）は VPN の IF にのみ bind する運用なので、公開ゾーンには
  出さない。**`--ui-addr 0.0.0.0:...` を指定すると hokora は警告ログを出す。**

---

## 5. ホストのメモリ→ディスク経路を塞ぐ

MK / KEK / DEK / secret はメモリ上にあるが、**swap・core dump・kdump で
ディスクに落ちうる**（THREAT_MODEL §5.3）。これらはアプリケーション側でも
同様に問題になる。

### 5.1 swap

- **システム全体の swap を無効化しない。** hokora は `mlockall` で自分の
  ページの swap-out を防ぐ（§2）。他プロセスまで巻き込む必要はない。
- どうしても暗号化 swap を使う場合は、**再起動ごとに鍵が変わる ephemeral key
  方式に限る**（永続鍵の暗号化 swap は、鍵ごと漏れれば無意味）。

### 5.2 core dump（systemd-coredump の無効化）

```bash
# ユニット単位では LimitCORE=0(§2)。ホスト全体でも無効化しておく
sudo systemctl mask systemd-coredump.socket
# /etc/security/limits.d/nocore.conf
echo '* hard core 0' | sudo tee /etc/security/limits.d/nocore.conf
```

### 5.3 kdump（kernel crash dump の無効化）

kdump が有効だと、パニック時に **物理メモリ全体**がディスクに書かれる。

```bash
# 確認
systemctl is-enabled kdump                 # enabled なら無効化する
cat /sys/kernel/kexec_crash_loaded         # 1 なら crash kernel がロード済み
cat /sys/kernel/kexec_crash_size           # 0 以外なら crash kernel 用に予約済み

# 無効化
sudo systemctl disable --now kdump
sudo grubby --update-kernel=ALL --remove-args=crashkernel
# 再起動後、kexec_crash_size が 0 になることを確認する
```

- **例外運用（kernel panic の調査時）:** どうしても必要なら
  `crashkernel=` を一時的に戻して調査し、**調査が終わったら必ず再無効化する**。
  有効なまま放置しない。

---

## 6. DNS レコード設計（Q6）

- 公開 DNS の `hokora.example.com` は **Machine API の public IP** を指す
  （certbot の DNS-01 と、アプリサーバーからの到達に使う）。到達制限は
  firewalld（§4）。
- **Web UI 用には、VPN 内 IP を指す別レコード**（例
  `hokora-ui.internal.example.com`）を用意する。
- **受容するトレードオフ:** VPN 内 IP が公開 DNS に載る軽微な情報漏れは
  受け入れる（内部 IP が分かっても、VPN に入れなければ到達できない）。公開
  ゾーンに秘匿すべき情報を載せない範囲で運用する。

---

## 7. TLS 証明書（certbot は別ホスト）

**証明書は別ホスト（Ansible 管理ホスト等）の certbot が Let's Encrypt DNS-01 で
取得する**（DESIGN §3.6）。DNS プロバイダの API 認証情報を hokora ホストに
置かないための構成である。

### 7.1 versioned directory + symlink（ペア単位の原子的切り替え）

証明書と秘密鍵は 2 ファイルで、個別 `rename` ではペアとして原子的にならない。
**versioned directory を作り、`current` symlink を rename で切り替える。**

```
/var/lib/hokora/tls/
├── 20260717-120000/{cert.pem,key.pem}
├── 20260915-120000/{cert.pem,key.pem}
└── current -> 20260915-120000        ← symlink の付け替えだけが原子的
```

### 7.2 deploy hook（新しい証明書の反映）

certbot の deploy hook は、hokora ホスト上で次を行う:

1. 新しい `YYYYMMDD-HHMMSS/` を作り `cert.pem` / `key.pem` を配置。
2. `ln -sfn <新dir> /var/lib/hokora/tls/current`（rename による原子的切り替え）。
3. `systemctl reload hokora`（= SIGHUP）。

- **リロードに失敗しても hokora は落ちない。** 古い有効な証明書を保持したまま
  動き続ける（DESIGN §3.7）。失敗は運用ログに出るので、そこで気づいて直す。

> 内部 CA を使う特殊構成では、クライアント側で `hokora-client get --ca <pem>` /
> `HOKORA_CA_FILE`（SDK は `WithRootCAs`）で信頼させる。**通常は公的 CA なので
> 不要。** `InsecureSkipVerify` 相当は存在しない。

---

## 8. クライアント（SDK / hokora-client）

**アプリホストにはサーバー本体（`hokora`）ではなく、クライアント専用バイナリ
`hokora-client` を配る。** `hokora-client` は標準ライブラリ + SDK のみに依存し、
SQLite / argon2 等のサーバー依存をリンクしない小さなバイナリである（サーバーの
`hokora` は約 20 MB、`hokora-client` は約 9 MB）。Go アプリは `hokora-client`
すら不要で、SDK を直接 import すればよい。

### 8.1 credential の解決順序

SDK・CLI は次の順で設定を解決する（先に見つかった値が勝つ）:

1. コード / フラグでの明示指定（`WithAddress` 等、`--addr` 等）
2. credential ファイル
   （systemd では `$CREDENTIALS_DIRECTORY/hokora` = `LoadCredential=` の展開先。
   `--credentials` / `WithCredentialsFile` でも指定可）
3. 環境変数（`HOKORA_ADDR` / `HOKORA_CLIENT_ID` / `HOKORA_CLIENT_SECRET` /
   `HOKORA_PROJECT` / `HOKORA_ENV`）

### 8.2 Go アプリ（推奨: SDK）

```go
client, err := hokora.New()          // $CREDENTIALS_DIRECTORY/hokora から解決
secrets, err := client.Fetch(ctx)
db := secrets.MustGetString("DATABASE_URL")
defer secrets.Zero()                 // best effort。GetString で取り出した値は消せない
```

- secret は **メモリ上の `[]byte`** に保持し、ディスクに書かず、キャッシュしない。
- `Zero()` は best effort（swap / core dump は防げない。§5、THREAT_MODEL 参照）。

### 8.3 `hokora-client get`（端末確認用）

```bash
sudo hokora-client get DATABASE_URL  # 値を 1 行 stdout に出す
```

- **端末での確認専用。** `hokora-client get KEY > file` のような**ファイル生成に
  使わない**（`.env` 出力＝`export` を実装しない方針と同じ理由）。

### 8.4 `hokora-client run`（既存アプリの移行用）

```bash
sudo hokora-client run -- /usr/local/bin/legacy-app --flag
```

- grant された secret を**子プロセスの環境変数に展開**して起動する。子の終了
  コードをそのまま返す。
- **限界（重要）:** 環境変数は **`/proc/<pid>/environ` から読める**。T1-a の
  攻撃者（アプリと同一 OS ユーザー）は secret 値そのものを取得できる
  （THREAT_MODEL R5）。**Go アプリでは SDK 方式を使うこと。** `hokora-client run`
  は SDK 化できない既存アプリの移行手段と位置づける。

### 8.5 Web UI は JavaScript を前提とする

bfcache 対策（`static/bfcache.js`）のため、**Web UI は JavaScript 有効を前提と
する**（DESIGN §9.3）。これは「JS は原則不要」の明示的な例外。無効だと、戻る
操作で平文が残りうる。

---

## 9. バックアップと復元（Q5）

### 9.1 バックアップ（online）

**hokora は暗号文のみを保存する。** バックアップに MK は含まれない（MK は
1Password にある）。**復元には「バックアップ + その時点で有効だった MK」の
両方が要る。**

`hokora backup` は SQLite の `VACUUM INTO` で、稼働中の DB から整合した
スナップショットを 1 ファイルに書き出す。**seal も停止も要らない**（暗号文だけを
対象にするので Vault には触れない。sealed 状態でも取れる）。単一ファイルに
まとまるため、`-wal` / `-shm` を取りこぼす余地も無い。

```bash
# サーバーは稼働したままでよい。--out は既存ファイルを上書きしない。
ssh vps "sudo -n hokora backup --out /var/lib/hokora/backups/hokora-$(date +%Y%m%d-%H%M%S).db"
# 手元へ引き取る（暗号文だが全 secret を含む。取り扱いは DB 本体と同じ）
scp vps:/var/lib/hokora/backups/hokora-YYYYmmdd-HHMMSS.db ./
```

- 出力ファイルは 0600 で作られ、親ディレクトリが無ければ 0700 で作られる。
  MK とは**別の場所**に保管する（両方が同じ場所で漏れたら封筒暗号の意味がない）。
- `hokora backup` は生成物を読み取り専用で開き直し、本バイナリと同じスキーマ版の
  DB として開けることだけ確認する。**これは復元テスト（§9.2）の代わりではない。**

#### offline 手順（フォールバック）

保守窓でサーバーを止められ、かつ `hokora backup` が使えない事情があるときは、
停止してファイルをコピーしてもよい。

```bash
# 1. seal(暗号操作を止め、DEK をゼロクリア)
ssh vps 'sudo -n hokora seal'
# 2. サービス停止(接続を閉じ、WAL をチェックポイントさせる)
ssh vps 'sudo systemctl stop hokora'
# 3. DB ファイル一式をコピー。**-wal / -shm も必ず含める**
ssh vps 'sudo tar czf - -C /var/lib/hokora hokora.db hokora.db-wal hokora.db-shm 2>/dev/null' \
  > "hokora-$(date +%Y%m%d-%H%M%S).tar.gz"
# 4. 再起動 → unseal
ssh vps 'sudo systemctl start hokora'
op read 'op://Infra/hokora/master-key' | ssh vps 'sudo -n hokora unseal --stdin'
```

- **`-wal` / `-shm` を取りこぼさない。** 停止後に WAL が消えている（チェック
  ポイント済み）なら `hokora.db` 単体でよいが、**確認せずに単体コピーしない**。
  迷ったら 3 ファイルまとめてコピーする。
- バックアップファイルのパーミッションを厳格にし、MK とは**別の場所**に保管する。

### 9.2 復元テスト（必須）

**「バックアップがある」は「復元できる」を意味しない。** 復元を実際に試すまで
R3 の緩和策は実態を持たない。別ホスト（または停止した検証環境）で:

```bash
sudo systemctl stop hokora
sudo tar xzf hokora-YYYYMMDD-HHMMSS.tar.gz -C /var/lib/hokora
sudo chown hokora:hokora /var/lib/hokora/hokora.db*
sudo systemctl start hokora
op read 'op://Infra/hokora/master-key' | sudo -n hokora unseal --stdin
sudo -n hokora status                       # state=unsealed になることを確認(status は状態のみ)
# secret が実際に復号できることは、grant のある machine credential で確認する:
#   hokora-client get --credentials /path/to/creds SOME_KEY
```

- **定期的に復元テストを回す。** バックアップ手順の劣化は、実際に復元するまで
  検出できない。

### 9.3 復元時の注意（R16 — 状態の巻き戻り）

**古いバックアップを復元すると、その時点の状態に巻き戻る。** 具体的には:

- 削除したはずの **grant が復活**する
- ローテーション済みの **旧 credential が復活**する
- 変更前の **パスワード**、**古いセッション**が復活する

復元後は必ず:

1. **全セッションを削除**（旧セッションの復活を消す。Web UI / 手順で）。
2. バックアップ取得後に行った **credential 再発行・grant 変更・ユーザー変更を
   再適用**する。
3. 侵害を機に復元したなら、§11 に従い**当該 secret を個別にローテーション**する。

---

## 10. MK のローテーション（R15 — 順序が重要）

**`hokora rotate-master` は新 MK を生成しない。** 生成は `gen-key`（DB に触ら
ない）。「生成 → DB 更新 → 保存前にクラッシュ」で全データが復旧不能になる事故を
避けるためである（DESIGN §6.7）。**次の順序を守る:**

```bash
# 1. 新 MK を生成(DB には触らない)。手順 3 で読む名前(master-key-new)に揃える
ssh vps 'hokora gen-key' | op document create --title 'hokora master-key-new'
# 2. 1Password への保存を確認(ここを飛ばさない)
# 3. 旧 MK と新 MK を stdin に 2 行で渡して rotate(改行区切り 2 行、2KB 上限)
{ op read 'op://Infra/hokora/master-key'; op read 'op://Infra/hokora/master-key-new'; } \
  | ssh vps 'sudo -n hokora rotate-master --stdin'
# 4. 新 MK で新しいバックアップを取得(§9.1)
# 5. その新バックアップで復元テスト(§9.2)
# 6. 旧バックアップを廃棄
# 7. 1Password の旧 MK を削除し、new を正式名にリネーム
```

- **rotate-master は専用 mutex で直列化される**（C10）。並行実行しても壊れない。
- **rotate に失敗した場合、旧 MK が引き続き有効**である。慌てて旧 MK を消さない。
- 手順 2（保存確認）と手順 5（復元テスト）を飛ばさない。**この順序が事故防止の
  本体である。**

---

## 11. 侵害・漏洩時の対応

### 11.1 secret / 権限の侵害（R13 — revoke の限界）

**revoke は「今後の取得」しか止めない。** 既に取得された secret は revoke では
戻らない。侵害された machine / grant があれば:

1. Web UI で当該 machine を**無効化**、または credential を**再発行**する
   （既存トークンは即座に無効になる）。不要な grant は**削除**する。
2. **当該 grant 範囲の secret を個別にローテーションする**（アプリ側の DB
   パスワード等を実際に変える）。revoke だけで安心しない。

### 11.2 TLS 秘密鍵の漏洩

- 別ホストの certbot で**証明書を失効（revoke）し、再発行**する。deploy hook で
  新しい versioned dir に配置し、`current` を切り替えて `systemctl reload hokora`
  （§7）。

### 11.3 MK の紛失

- **MK を失うと、暗号文は復号できない。復旧は不能。** これは設計上の性質であり、
  hokora 側に裏口はない。だからこそ MK の 1Password 保管と、rotate 手順（§10）の
  保存確認を徹底する。

---

## 12. 監査ログの見方（V4 は運用で実現する）

- 監査ログは **削除できない**（削除機能を実装していない。AGENTS.md ルール 28）。
- **`success` は「secret の送信を開始した」の意味**であって、「相手が確かに
  受け取った」ではない（THREAT_MODEL §10.5）。ネットワーク切断等で相手に
  届かなくても success になりうる。
- 認証失敗で存在しない client_id / username が来た場合、`actor` は `anonymous` と
  記録され、生の入力値は入らない。相関には `subject_digest`
  （`hex(SHA-256(input)[:8])`）を使う（AGENTS.md ルール 25）。**User-Agent は
  記録しない。**
- **grant は最小化して運用する**（V2 は運用でのみ実現される）。使わなくなった
  grant は放置せず削除する。

---

## 13. トラブルシューティング

| 症状 | 見るところ |
|------|-----------|
| 起動直後に終了し `mlockall failed (LimitMEMLOCK=infinity is required)` | unit の `LimitMEMLOCK=infinity`（§2）。手元検証は root か `ulimit -l unlimited` が要る |
| unseal したのに `sudo` がパスワードを聞いて MK が消費される | `sudo -n` と NOPASSWD sudoers（§3.1）。プロンプトが stdin を食っている |
| アプリが 401 を受ける | credential 再発行・machine 無効化でトークンが消えていないか。credential 解決順序（§8.1）で意図した値が読めているか |
| アプリが 403 を受ける | grant の有無、project / environment が論理削除されていないか（削除は grant なしと同じ 403） |
| Machine API が 503 / `sealed` | サーバーが sealed。unseal する（§3） |
| 証明書更新後もエラー | SIGHUP のリロードに失敗し**旧証明書のまま**動いている可能性。運用ログを見て cert/key のペアと `current` symlink を確認（§7） |
| Web UI で戻ると平文が残る | JavaScript が無効になっていないか（§8.5、DESIGN §9.3） |
| firewalld を入れたのにアプリから届かない | rich rule の source / port と適用ゾーン（§4）。`firewall-cmd --list-rich-rules` |
