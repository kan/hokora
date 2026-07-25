package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// run() は main() の外側にあるディスパッチ本体である。cmdGet / cmdBulk /
// cmdRun それぞれの単体テストは「渡された引数をどう処理するか」までしか
// 見ておらず、「main.go の switch が正しいハンドラに繋いでいるか」という
// 配線そのものは別の関心事(AGENTS.md の教訓: 部品の単体テストは配線を
// 検証しない)。ここでは run() を直接叩き、fake サーバーへの実際の往復を
// 通してディスパッチを検証する。

// s.args() は「サブコマンドの後に続くフラグ」を組み立てるヘルパーなので、
// run() へ渡す際は先頭にサブコマンド名を足す。
func dispatchArgs(cmd string, s *clientTestServer, rest ...string) []string {
	return append([]string{cmd}, s.args(rest...)...)
}

func TestRunDispatchesToBulk(t *testing.T) {
	s := newClientTestServer(t)

	var err error
	stdout := captureStdout(t, func() {
		err = run(context.Background(), dispatchArgs("bulk", s))
	})
	if err != nil {
		t.Fatalf("run bulk: %v", err)
	}
	var got map[string]string
	if jsonErr := json.Unmarshal([]byte(stdout), &got); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v (%q)", jsonErr, stdout)
	}
	if got["DATABASE_URL"] != testDBURL {
		t.Errorf("DATABASE_URL = %q, want %q", got["DATABASE_URL"], testDBURL)
	}
}

func TestRunDispatchesToGet(t *testing.T) {
	s := newClientTestServer(t)

	var err error
	stdout := captureStdout(t, func() {
		err = run(context.Background(), dispatchArgs("get", s, "DATABASE_URL"))
	})
	if err != nil {
		t.Fatalf("run get: %v", err)
	}
	if want := testDBURL + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestRunDispatchesToRun(t *testing.T) {
	s := newClientTestServer(t)

	var err error
	stdout := captureStdout(t, func() {
		err = run(context.Background(), dispatchArgs("run", s, "--", "sh", "-c", `printf '%s' "$DATABASE_URL"`))
	})
	if err != nil {
		t.Fatalf("run run: %v", err)
	}
	if stdout != testDBURL {
		t.Errorf("stdout = %q, want %q", stdout, testDBURL)
	}
}

// 引数無しはエラーになる(usage を表示して終了コード非ゼロにする main() の
// 前提)。
func TestRunNoCommandGiven(t *testing.T) {
	var err error
	captureStdout(t, func() {
		err = run(context.Background(), nil)
	})
	if err == nil {
		t.Fatal("run with no args succeeded")
	}
}

// 未知のサブコマンドはエラーになる(default ケースの配線)。
func TestRunUnknownCommand(t *testing.T) {
	var err error
	captureStdout(t, func() {
		err = run(context.Background(), []string{"frobnicate"})
	})
	if err == nil {
		t.Fatal("run with an unknown command succeeded")
	}
}

// help / -h / --help はいずれも usage を stdout に出し、エラーにならない。
func TestRunHelpVariants(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			var err error
			stdout := captureStdout(t, func() {
				err = run(context.Background(), []string{arg})
			})
			if err != nil {
				t.Fatalf("run %s = %v, want nil", arg, err)
			}
			if !strings.Contains(stdout, "hokora-client") {
				t.Errorf("stdout = %q, want usage text", stdout)
			}
			// Commands セクションに bulk が載っていること(main.go の
			// usage 定数を更新し忘れていないかの裏取り)。
			if !strings.Contains(stdout, "bulk") {
				t.Errorf("stdout = %q, want it to document the bulk command", stdout)
			}
		})
	}
}
