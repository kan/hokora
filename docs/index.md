# hokora マニュアル

hokora は、単一の組織で使う秘匿情報（secret）の管理サーバーです。
アプリケーションサーバーの設定ファイルに並んでいた複数の secret を、失効できる 1 個の credential に置き換えます。
アプリは起動時にその credential で hokora へ認証し、割り当てられた secret をメモリ上に受け取ります。

このマニュアルは、hokora を使う人に向けて、用語と日々の操作をまとめたものです。
サーバーの構築、バックアップ、障害時の対応は [運用 Runbook](OPERATIONS.md) に書いてあります。

## 目次

| ページ | 内容 |
|---|---|
| [用語集](manual/glossary.md) | hokora の文書と画面に出てくる言葉の意味。Web UI の日本語表示との対応 |
| [Web UI の使い方](manual/web-ui.md) | ログインから、secret の登録、マシンとアクセス権の管理、監査ログの確認まで |
| [アプリから secret を取得する](manual/clients.md) | Go SDK と `hokora-client` の使い分け、credential の置き方 |
| [コマンド一覧](manual/cli.md) | `hokora` と `hokora-client` のサブコマンドとフラグ |

設計と運用の文書は次のとおりです。

| 文書 | 内容 |
|---|---|
| [脅威モデル](THREAT_MODEL.md) | 何から守り、何を守らないか。導入の前に読んでください |
| [運用 Runbook](OPERATIONS.md) | systemd、firewalld、TLS、バックアップと復元、鍵のローテーション、侵害時の対応 |
| [設計文書](DESIGN.md) | アーキテクチャ、データモデル、暗号設計、API 仕様 |
| [ロードマップ](ROADMAP.md) | マイルストーンと範囲 |

## hokora がすること

- secret を暗号化して保存します。
  DB に入るのは暗号文だけです。
  復号に使うマスターキーは人がパスワードマネージャで保管し、hokora はディスクに書きません
- マシンごとに credential を発行し、取得できる範囲を割り当てます。
  credential は無効化と再発行ができます
- secret の読み取りを、失敗も含めて監査ログに記録します
- 人が操作する Web UI を持ちます。
  VPN の内側からだけ届く場所に置きます

## hokora がしないこと

hokora が守る範囲は広くありません。
次のことは hokora では防げません。

- **アプリと同じ OS ユーザーの権限を取った攻撃者は、そのマシンに割り当てた secret を取得できます。**
  credential を読めるからです（secret zero problem）。
  Vault や Infisical でも同じです
- アプリサーバー側のディスクへの漏洩は管理しません。
  swap、core dump、kdump でメモリの内容がディスクに出る経路は、アプリサーバーの設定で塞ぐ必要があります
- **無効化や権限の削除で止まるのは、それ以降の取得だけです。**
  取得済みの secret は相手の手元に残るので、漏れた疑いがある secret は 1 つずつ作り直します
- 冗長化、クラスタ、複数組織での利用には対応しません

詳しくは [脅威モデル](THREAT_MODEL.md) を読んでください。

## 全体の構成

```
                     VPN                          公開(firewall で制限)
  ┌──────────────┐   :8443  ┌───────────────┐  :9443  ┌──────────────┐
  │ 運用者        │────────▶│  hokora        │◀────────│ アプリサーバー │
  │ (ブラウザ)    │  Web UI │  (単一の       │ Machine │ hokora-client │
  └──────────────┘         │   バイナリ)    │   API   │  または SDK   │
                            │                │         └──────────────┘
        root のみ ─────────▶│ admin socket   │
        (unseal / seal)     │  SQLite(暗号文)│
                            └───────────────┘
```

hokora への接続先は 3 つあります。

| 接続先 | 使う人 | 用途 |
|---|---|---|
| Web UI（既定は `:8443`） | 運用者 | secret、マシン、アクセス権、ユーザーの管理と、監査ログの閲覧 |
| Machine API（既定は `:9443`） | アプリ | credential で認証して secret を取得する |
| admin socket（Unix ソケット） | サーバー上の root | `hokora unseal` / `seal` / `status` / `rotate-master` |

## 使い始めるまでの流れ

1. サーバーを構築します（[運用 Runbook](OPERATIONS.md) の §1 と §2）。
   `hokora init` がマスターキーと初期 admin のパスワードを 1 回だけ出力します
2. Web UI にログインし、パスワードを変更して、unseal します（[Web UI の使い方](manual/web-ui.md)）
3. プロジェクト、環境、item を作り、secret を登録します
4. マシンを作り、credential を受け取って、アプリサーバーに置きます
5. アプリから secret を取得します（[アプリから secret を取得する](manual/clients.md)）
