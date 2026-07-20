package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// adminRequestTimeout は admin socket への 1 リクエストの上限である。
// unseal / rotate-master は argon2 を伴い、待ち行列に入ることもある。
const adminRequestTimeout = 60 * time.Second

// newAdminClient は unix socket 上で HTTP を話すクライアントを作る。
//
// ホスト名は使わないが、http.Client は URL を要求するのでダミーを使う
// (DialContext が常に socket へ繋ぐため、この名前は解決されない)。
func newAdminClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: adminRequestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// adminCall は admin socket に 1 リクエストを送り、レスポンスを解釈する。
//
// body は呼び出し側が用意する。**MK を含みうるので、呼び出し側が Zero する。**
func adminCall(ctx context.Context, socketPath, method, path string, body []byte) (_ *adminStatusResponse, err error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://admin"+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build admin request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	resp, err := newAdminClient(socketPath).Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to admin socket %s: %w", socketPath, err)
	}
	defer func() {
		// Close の失敗は接続の後始末の問題であり、状態は既に変わっている。
		// 握りつぶさず、他にエラーが無ければそれを返す。
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close admin response: %w", cerr)
		}
	}()

	// レスポンスは status か error のどちらか。どちらも小さいので上限をかけて読む。
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return nil, fmt.Errorf("read admin response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var e adminErrorResponse
		if err := json.Unmarshal(raw, &e); err != nil || e.Error == "" {
			return nil, fmt.Errorf("admin request failed with status %d", resp.StatusCode)
		}
		return nil, errors.New(e.Error)
	}

	var status adminStatusResponse
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, fmt.Errorf("parse admin response: %w", err)
	}
	return &status, nil
}

// adminFlags は admin socket を使うコマンド共通のフラグを組み立てる。
func adminFlags(name string) (*flag.FlagSet, *string) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", DefaultAdminSocket, "path to the admin unix socket")
	return flags, socket
}

// requireStdinFlag は --stdin を宣言し、その検査を行う関数を返す。
//
// --stdin は「秘密をどこから読むか」を明示させるためのフラグである。既定値を
// 持たせず、**他の入力経路を足せないことを呼び出し側に示す**(AGENTS.md
// ルール 9-12。引数は ps で見え、環境変数は /proc/<pid>/environ に残る)。
func requireStdinFlag(flags *flag.FlagSet, what string) func() error {
	stdin := flags.Bool("stdin", false, "read "+what+" from stdin (required)")
	return func() error {
		if !*stdin {
			return fmt.Errorf("%s: --stdin is required (%s is only read from stdin)", flags.Name(), what)
		}
		return nil
	}
}

// parseFlags はフラグを解釈する。-h は usage を出して正常終了する。
//
// handled が true なら、呼び出し側は err をそのまま返して終わる。
func parseFlags(flags *flag.FlagSet, args []string) (handled bool, err error) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(os.Stdout)
			flags.Usage()
			return true, nil
		}
		return true, fmt.Errorf("%s: %w", flags.Name(), err)
	}
	if flags.NArg() > 0 {
		return true, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return false, nil
}

// cmdUnseal は stdin から MK を読み、admin socket へ送る。
//
// **MK は stdin からのみ受け取る**(AGENTS.md ルール 9-12)。コマンドライン
// 引数は ps で全ユーザーから見え、環境変数は /proc/<pid>/environ に残る。
func cmdUnseal(ctx context.Context, args []string) error {
	flags, socket := adminFlags("unseal")
	stdin := requireStdinFlag(flags, "the master key")
	if handled, err := parseFlags(flags, args); handled {
		return err
	}
	if err := stdin(); err != nil {
		return err
	}

	mk, err := readStdinLimited(maxUnsealBody)
	if err != nil {
		return fmt.Errorf("unseal: %w", err)
	}
	defer Zero(mk)

	status, err := adminCall(ctx, *socket, http.MethodPost, "/unseal", mk)
	if err != nil {
		return fmt.Errorf("unseal: %w", err)
	}
	printAdminStatus(status)
	return nil
}

// cmdSeal は DEK を破棄させる。緊急遮断操作なので、余計な確認を挟まない。
func cmdSeal(ctx context.Context, args []string) error {
	return adminSimpleCommand(ctx, args, "seal", http.MethodPost, "/seal")
}

// cmdStatus は現在の状態を表示する。
func cmdStatus(ctx context.Context, args []string) error {
	return adminSimpleCommand(ctx, args, "status", http.MethodGet, "/status")
}

// adminSimpleCommand はボディを持たない admin コマンドを実行する。
func adminSimpleCommand(ctx context.Context, args []string, name, method, path string) error {
	flags, socket := adminFlags(name)
	if handled, err := parseFlags(flags, args); handled {
		return err
	}

	status, err := adminCall(ctx, *socket, method, path, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	printAdminStatus(status)
	return nil
}

// cmdRotateMaster は現行 MK と新 MK を stdin から読み、admin socket へ送る。
//
// **新 MK を生成しない**(AGENTS.md ルール 18)。生成は `hokora gen-key` の
// 責務であり、人間が 1Password への保存を確認してからこれを実行する。
// 「生成 → DB 更新 → 保存前にクラッシュ」で全データが復旧不能になる事故を
// 防ぐための分離である。
func cmdRotateMaster(ctx context.Context, args []string) error {
	flags, socket := adminFlags("rotate-master")
	stdin := requireStdinFlag(flags, "master keys")
	if handled, err := parseFlags(flags, args); handled {
		return err
	}
	if err := stdin(); err != nil {
		return err
	}

	body, err := readStdinLimited(maxRotateBody)
	if err != nil {
		return fmt.Errorf("rotate-master: %w", err)
	}
	defer Zero(body)

	status, err := adminCall(ctx, *socket, http.MethodPost, "/rotate-master", body)
	if err != nil {
		return fmt.Errorf("rotate-master: %w", err)
	}
	fmt.Println("master key rotated")
	fmt.Fprintln(os.Stderr,
		"take a new backup, verify a restore with the new master key, "+
			"discard the old backup, and only then delete the old master key")
	printAdminStatus(status)
	return nil
}

// readStdinLimited は stdin を上限つきで読む。
//
// 上限を超えたら **切り詰めずにエラーにする。** 黙って切り詰めると、
// 「壊れた MK で unseal を試みて失敗する」という分かりにくい結果になる。
func readStdinLimited(limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(os.Stdin, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if int64(len(body)) > limit {
		Zero(body)
		return nil, fmt.Errorf("stdin exceeds %d bytes", limit)
	}
	if len(body) == 0 {
		return nil, errors.New("stdin is empty")
	}
	return body, nil
}

func printAdminStatus(s *adminStatusResponse) {
	if s.DEKVersion > 0 {
		fmt.Printf("state=%s dek_version=%d tokens=%d\n", s.State, s.DEKVersion, s.Tokens)
		return
	}
	fmt.Printf("state=%s tokens=%d\n", s.State, s.Tokens)
}
