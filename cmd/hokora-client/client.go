package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

	sdk "github.com/kan/hokora/sdk"
)

// DefaultCredentialsFile はクライアント側 credential の既定の位置である
// (DESIGN §10.2)。root:0600 に置かれるため、人間が使う場合は `sudo` になる。
//
//nolint:gosec // G101: 認証情報そのものではなく、ファイルパスである
const DefaultCredentialsFile = "/etc/hokora/credentials"

// envCAFile は内部 CA の PEM ファイルパスを指す環境変数。--ca の既定値。
const envCAFile = "HOKORA_CA_FILE"

// clientOptions は get / run 共通のフラグを組み立てる。
//
// **credential は SDK の解決順序に委ねる**(Option → ファイル →
// 環境変数)。CLI は既定のファイルパスを Option として渡すだけで、
// project / env / addr の上書きフラグも用意する。
//
// 返す関数は CA ファイルの読み込みで失敗しうるため error を返す。
func clientOptions(flags *flag.FlagSet) func() ([]sdk.Option, error) {
	credFile := flags.String("credentials", DefaultCredentialsFile,
		"path to the credentials file (KEY=VALUE lines)")
	addr := flags.String("addr", "", "override HOKORA_ADDR")
	project := flags.String("project", "", "override HOKORA_PROJECT")
	env := flags.String("env", "", "override HOKORA_ENV")
	// 既定は公的 CA(システムルート)。内部 CA を使う場合のみ PEM を渡す。
	// **--ca を渡すと、その CA だけを信頼する**(システムルートは無効になる)。
	caFile := flags.String("ca", os.Getenv(envCAFile),
		"PEM file of an internal CA to trust exclusively (default $HOKORA_CA_FILE; system roots used when unset)")

	return func() ([]sdk.Option, error) {
		opts := []sdk.Option{sdk.WithCredentialsFile(*credFile)}
		if *addr != "" {
			opts = append(opts, sdk.WithAddress(*addr))
		}
		if *project != "" {
			opts = append(opts, sdk.WithProject(*project))
		}
		if *env != "" {
			opts = append(opts, sdk.WithEnv(*env))
		}
		if *caFile != "" {
			pool, err := loadCAPool(*caFile)
			if err != nil {
				return nil, err
			}
			opts = append(opts, sdk.WithRootCAs(pool))
		}
		return opts, nil
	}
}

// loadCAPool は PEM ファイルから証明書プールを作る。**システムルートは
// 含めない**(内部 CA だけを信頼したい構成を想定)。この空プールを SDK の
// WithRootCAs に渡すと、サーバー検証はこの CA だけを使う(システムルートは
// 無効になる。x509.CertPool は後からシステムルートと合成できないため)。
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) //nolint:gosec // G304: 運用者が明示指定した CA ファイル
	if err != nil {
		return nil, fmt.Errorf("read ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

// commandFlags は共通フラグ付きの FlagSet を作る。エラー文言は自前で整形する
// ため FlagSet 自身の出力は捨てる(--help のときだけ stdout に戻す)。
func commandFlags(name string) (*flag.FlagSet, func() ([]sdk.Option, error)) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags, clientOptions(flags)
}

// parseFlags は引数を解析する。done=true は「呼び出し側はここで戻ってよい」を
// 意味する(`--help` は usage を stdout に出して err=nil、解析失敗は err 付き)。
func parseFlags(flags *flag.FlagSet, args []string) (done bool, err error) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stdout)
			flags.Usage()
			return true, nil
		}
		return true, fmt.Errorf("%s: %w", flags.Name(), err)
	}
	return false, nil
}

// secretsToMap は SDK の Secrets を map[string]string にする。
//
// **ここで作る文字列は Zero() で消せない**(Go の string は不変。SDK の
// GetString の godoc が述べているとおり)。それでも GetString を使うのは、
// JSON へのエンコード(bulk)も子プロセスの環境変数(run)も **Go の string を
// 要求する**ためで、[]byte のまま渡す経路が無いからである
// (encoding/json は []byte を base64 にしてしまう)。
func secretsToMap(secrets *sdk.Secrets) map[string]string {
	values := make(map[string]string, secrets.Len())
	for _, key := range secrets.Keys() {
		value, _ := secrets.GetString(key)
		values[key] = value
	}
	return values
}

// cmdGet は単一の secret を stdout に出力する。
//
// **端末での確認用である**(DESIGN §10。`hokora-client get KEY > file` のような
// ファイル生成に使ってはならない。`export` を実装しない理由と同じ)。
func cmdGet(ctx context.Context, args []string) error {
	flags, buildOpts := commandFlags("get")
	if done, err := parseFlags(flags, args); done {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: hokora-client get [flags] KEY")
	}
	key := flags.Arg(0)

	opts, err := buildOpts()
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	client, err := sdk.New(opts...)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	// **単一キー取得を使う**(bulk Fetch ではない)。get 1 件で grant 内の全
	// キーを read・監査してしまうと、監査ログが実態と乖離する(THREAT_MODEL
	// §10.5: success は「漏洩したかもしれない」記録)。存在しないキーは grant
	// なしと同じ forbidden になる(サーバーが存在情報を漏らさない)。
	secrets, err := client.FetchKey(ctx, key)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer secrets.Zero()

	value, ok := secrets.Get(key)
	if !ok {
		return fmt.Errorf("get: no secret named %q", key)
	}

	// **改行を 1 つだけ付けて出す。** 端末での確認が目的なので読みやすさを
	// 優先する。ファイルへリダイレクトしての利用は想定しない。
	if _, err := fmt.Fprintf(os.Stdout, "%s\n", value); err != nil {
		return fmt.Errorf("get: %w", err)
	}
	return nil
}

// cmdBulk は grant された secret を **JSON オブジェクト 1 個**として stdout に
// 出力する(`{"KEY":"value",...}` + 改行)。key は昇順に並ぶ
// (encoding/json が map のキーをソートするため)。
//
// **用途は、SDK 化できない既存アプリの設定ファイルからパイプで読むことである。**
// 例えば Perl の `config/base.pl` から
// `open my $fh, '-|', 'hokora-client', 'bulk'` で読む。`get` を key の数だけ
// 呼ぶと、その都度 認証 + HTTP 往復が発生するため、これを 1 回にまとめる。
//
// **監査の粒度に注意する。** bulk は `/v1/secrets` を使うので、**grant 内の全
// key が read として監査記録に残る**(`get` は指定した 1 key だけ)。プロセス
// 起動のたびに全 key 分の監査行が増えることを織り込んで使う
// (THREAT_MODEL §10.5: success は「漏洩したかもしれない」記録)。
//
// **ファイル生成に使ってはならない**(`hokora-client bulk > secrets.json` は
// `export` を実装しない方針そのものに反する。DESIGN §10)。読み手のプロセスへ
// パイプで渡し、ディスクに落とさない。
func cmdBulk(ctx context.Context, args []string) error {
	flags, buildOpts := commandFlags("bulk")
	if done, err := parseFlags(flags, args); done {
		return err
	}
	// 位置引数は取らない。**key を絞る指定は用意しない**: サーバー側は
	// bulk エンドポイントで全 key を返し・監査するため、クライアントで
	// 間引いても読まれた事実は変わらない。「絞れば露出が減る」と誤解させる
	// 見せかけの機能を作らない。
	if flags.NArg() != 0 {
		return errors.New("usage: hokora-client bulk [flags]")
	}

	opts, err := buildOpts()
	if err != nil {
		return fmt.Errorf("bulk: %w", err)
	}
	client, err := sdk.New(opts...)
	if err != nil {
		return fmt.Errorf("bulk: %w", err)
	}
	secrets, err := client.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("bulk: %w", err)
	}
	defer secrets.Zero()

	values := secretsToMap(secrets)

	// **一旦バッファに組み立ててから 1 回で書く。** 途中でエンコードに失敗した
	// ときに、壊れた JSON の断片を stdout に残さないため。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// HTML エスケープを切る。既定では `&` `<` `>` が Unicode エスケープ形式に
	// 置き換わる。パーサは同じ値に復元するので JSON としては同値だが、URL 等を
	// 目視・grep で確認できるよう、値をそのままの形で出す。
	enc.SetEscapeHTML(false)
	if err := enc.Encode(values); err != nil {
		// map[string]string のエンコードは値に起因して失敗しない
		// (不正な UTF-8 は U+FFFD に置換される)。値がエラー文言に混ざる
		// 経路は無い。
		return fmt.Errorf("bulk: encode secrets: %w", err)
	}
	// values の string は消せない(secretsToMap のコメント)が、消せるバッファは
	// 消す(best effort)。
	defer zeroBytes(buf.Bytes())

	if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("bulk: write stdout: %w", err)
	}
	return nil
}

// zeroBytes は best effort でバッファを上書きする(SDK の Secrets.Zero と
// 同じ位置づけ。swap / core dump は防げない)。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// cmdRun は secret を環境変数に展開して子プロセスを起動する(移行用)。
//
// **T1-a の攻撃者が /proc/<pid>/environ から secret 値そのものを読める**
// (THREAT_MODEL R5)。これは V1 を無効化する。**Go アプリケーションでは
// SDK 方式を使うこと。** hokora-client run は既存アプリの移行用と位置づける。
func cmdRun(ctx context.Context, args []string) error {
	flags, buildOpts := commandFlags("run")
	if done, err := parseFlags(flags, args); done {
		return err
	}

	// `hokora-client run [flags] -- cmd args...` の形。-- 以降が起動するコマンド。
	command := flags.Args()
	if len(command) == 0 {
		return errors.New("usage: hokora-client run [flags] -- COMMAND [args...]")
	}

	opts, err := buildOpts()
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	client, err := sdk.New(opts...)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	secrets, err := client.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	// 子プロセスの環境に secret を足す。**親の環境は変更しない。**
	childEnv := os.Environ()
	for key, value := range secretsToMap(secrets) {
		childEnv = append(childEnv, key+"="+value)
	}
	// SDK 側のバッファは消す(childEnv の string には残るが、それは
	// 子プロセスに渡すために不可避である)。
	secrets.Zero()

	bin, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	//nolint:gosec // G204: 実行対象は運用者が -- の後に明示的に指定したコマンドである
	cmd := exec.CommandContext(ctx, bin, command[1:]...)
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// 子プロセスの終了コードをそのまま返す。子がシグナルで殺された場合は
		// ExitCode() が -1 を返し、os.Exit(-1) は 255 になる(シグナル番号は
		// 失われる)。移行補助コマンドとしては許容する。
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("run: %w", err)
	}
	return nil
}
