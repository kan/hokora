package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureOutput は f の実行中に os.Stdout / os.Stderr を差し替え、書き込まれた
// 内容を文字列として返す。os.Stdout / os.Stderr はパッケージ変数なので、
// t.Parallel() を呼ぶ他のテストと同時に走ると出力が混線する。このヘルパーを
// 使うテストは t.Parallel() を呼ばないこと(Go のテストランナーは、並列化して
// いない top-level テストを、並列テスト群を動かす前に順番に完走させるため、
// これを守れば競合しない)。
func captureOutput(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()

	origOut, origErr := os.Stdout, os.Stderr
	t.Cleanup(func() { os.Stdout, os.Stderr = origOut, origErr })

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW

	f()

	outW.Close()
	errW.Close()
	outBytes, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	errBytes, err := io.ReadAll(errR)
	if err != nil {
		t.Fatalf("read stderr pipe: %v", err)
	}
	return string(outBytes), string(errBytes)
}

// run(nil) はエラーを返し、使い方を stderr に出す。「エラーは返すが usage は
// 出さない」実装に戻ると、対話的に打ち間違えたユーザーが何も手がかりを得られなく
// なるので、両方を確認する。
func TestRunWithNoArgsPrintsUsageAndErrors(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() {
		err = run(t.Context(), nil)
	})

	if err == nil {
		t.Fatal("run(nil) = nil, want an error")
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr = %q, want it to contain usage text", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

// help / -h / --help は失敗ではない。usage を stdout に出して 0 で終了しなければ
// ならない(main() は err != nil のときだけ os.Exit(1) するため)。
func TestRunHelpVariantsSucceedAndPrintUsageToStdout(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			var err error
			stdout, stderr := captureOutput(t, func() {
				err = run(t.Context(), []string{arg})
			})

			if err != nil {
				t.Errorf("run(%q) = %v, want nil", arg, err)
			}
			if !strings.Contains(stdout, "Usage:") {
				t.Errorf("stdout = %q, want it to contain usage text", stdout)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		})
	}
}

// 未知のコマンドはエラーを返し、usage を stderr に出す。エラーメッセージに
// 入力されたコマンド名が含まれないと、何を打ち間違えたのか利用者に伝わらない。
func TestRunWithUnknownCommand(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() {
		err = run(t.Context(), []string{"bogus-command"})
	})

	if err == nil {
		t.Fatal("run with an unknown command = nil, want an error")
	}
	if !strings.Contains(err.Error(), "bogus-command") {
		t.Errorf("error = %v, want it to name the unknown command", err)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr = %q, want it to contain usage text", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

// get / run は **サーバーバイナリの責務ではない**。クライアント専用の
// hokora-client バイナリ(cmd/hokora-client)へ分離したので、root の hokora
// では未知コマンドとして扱われること(= 誤って再統合していないこと)を
// 固定する。サーバー本体に sqlite / argon2 を積んだままアプリホストへ
// 配る事態を防ぐための境界である。
func TestServerBinaryDoesNotHandleClientCommands(t *testing.T) {
	for _, cmd := range []string{"get", "run"} {
		t.Run(cmd, func(t *testing.T) {
			err := run(t.Context(), []string{cmd})
			if err == nil {
				t.Fatalf("run(%q) = nil, want an unknown-command error", cmd)
			}
			if !strings.Contains(err.Error(), "unknown command") {
				t.Errorf("error = %v, want an unknown-command error", err)
			}
		})
	}
}

// run が "init" をそのサブコマンドの引数(rest)に正しく振り分けることを、
// 実際に DB が初期化されることで確認する。cmd, rest := args[0], args[1:] の
// スライシングを間違えると、フラグがコマンド名に食われて崩れる。
func TestRunDispatchesInitWithItsArgs(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/hokora.db"

	var err error
	stdout, stderr := captureOutput(t, func() {
		err = run(t.Context(), []string{"init", "-db", path})
	})

	if err != nil {
		t.Fatalf("run([init -db %s]) = %v, want nil", path, err)
	}
	// **stdout に出るのはマスターキーだけである。** パイプで
	// パスワードマネージャへ渡せるよう、説明文は stderr へ出す。
	if _, err := DecodeMasterKey([]byte(stdout)); err != nil {
		t.Errorf("stdout = %q, want a single master key: %v", stdout, err)
	}
	if !strings.Contains(stderr, path) {
		t.Errorf("stderr = %q, want it to mention %q", stderr, path)
	}

	store, openErr := OpenStore(t.Context(), path)
	if openErr != nil {
		t.Fatalf("OpenStore after run(init): %v", openErr)
	}
	store.Close()
}

// M3 で実装されたサブコマンドが run から振り分けられていること。
//
// gen-key は DB に触らないので、ここで実際に動かして確認できる。**鍵は
// stdout に、注意書きは stderr に出る**(パイプでパスワードマネージャへ
// 渡す運用のため)。
func TestRunDispatchesGenKey(t *testing.T) {
	var err error
	stdout, stderr := captureOutput(t, func() {
		err = run(t.Context(), []string{"gen-key"})
	})
	if err != nil {
		t.Fatalf("run([gen-key]) = %v, want nil", err)
	}

	mk, decodeErr := DecodeMasterKey([]byte(stdout))
	if decodeErr != nil {
		t.Fatalf("stdout = %q, want a single master key: %v", stdout, decodeErr)
	}
	if len(mk) != MasterKeyBytes {
		t.Errorf("master key length = %d, want %d", len(mk), MasterKeyBytes)
	}
	if strings.Contains(stderr, strings.TrimSpace(stdout)) {
		t.Error("stderr repeats the master key")
	}
	if !strings.Contains(stderr, "password manager") {
		t.Errorf("stderr = %q, want it to tell the operator to store the key", stderr)
	}
}

// admin socket を使うコマンドは、サーバーが居なければ接続エラーで終わる。
// **未実装扱いにはならない**(振り分けが届いていることの確認)。
func TestRunDispatchesAdminCommands(t *testing.T) {
	socket := t.TempDir() + "/absent.sock"

	for _, args := range [][]string{
		{"status", "-socket", socket},
		{"seal", "-socket", socket},
	} {
		t.Run(args[0], func(t *testing.T) {
			err := run(t.Context(), args)
			if err == nil {
				t.Fatalf("run(%v) = nil, want a connection error", args)
			}
			if !strings.Contains(err.Error(), socket) {
				t.Errorf("error = %v, want it to name the socket path", err)
			}
		})
	}
}

// unseal / rotate-master は --stdin を明示しないと動かない。
// MK の入力経路を stdin だけに限っていることを、フラグの形でも示す。
func TestUnsealRequiresStdinFlag(t *testing.T) {
	for _, cmd := range []string{"unseal", "rotate-master"} {
		t.Run(cmd, func(t *testing.T) {
			err := run(t.Context(), []string{cmd})
			if err == nil {
				t.Fatalf("run(%q) = nil, want an error", cmd)
			}
			if !strings.Contains(err.Error(), "--stdin") {
				t.Errorf("error = %v, want it to require --stdin", err)
			}
		})
	}
}
