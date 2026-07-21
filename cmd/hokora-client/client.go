package main

import (
	"context"
	"crypto/x509"
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

// cmdGet は単一の secret を stdout に出力する。
//
// **端末での確認用である**(DESIGN §10。`hokora-client get KEY > file` のような
// ファイル生成に使ってはならない。`export` を実装しない理由と同じ)。
func cmdGet(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	buildOpts := clientOptions(flags)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stdout)
			flags.Usage()
			return nil
		}
		return fmt.Errorf("get: %w", err)
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

	secrets, err := client.Fetch(ctx)
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

// cmdRun は secret を環境変数に展開して子プロセスを起動する(移行用)。
//
// **T1-a の攻撃者が /proc/<pid>/environ から secret 値そのものを読める**
// (THREAT_MODEL R5)。これは V1 を無効化する。**Go アプリケーションでは
// SDK 方式を使うこと。** hokora-client run は既存アプリの移行用と位置づける。
func cmdRun(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	buildOpts := clientOptions(flags)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stdout)
			flags.Usage()
			return nil
		}
		return fmt.Errorf("run: %w", err)
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
	for _, key := range secrets.Keys() {
		value, _ := secrets.GetString(key)
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
