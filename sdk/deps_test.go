package hokora_test

import (
	"os/exec"
	"strings"
	"testing"
)

// **SDK は標準ライブラリのみに依存する**(AGENTS.md)。
//
// SDK を import するアプリに、サーバー本体の依存(modernc.org/sqlite 等)を
// 引き込ませないための不変条件である。`go list -deps .` を走らせ、標準
// ライブラリと SDK 自身以外のパッケージが無いことを確かめる。
//
// 判定: サードパーティのパッケージはインポートパスの **先頭要素にドメイン
// (ドット)を持つ**(github.com/... 等)。標準ライブラリは持たない
// (net/http、crypto/internal/... 等)。SDK 自身だけは例外として許す。
func TestSDKDependsOnlyOnTheStandardLibrary(t *testing.T) {
	t.Parallel()

	out := goList(t, "-deps", ".")

	var external []string
	for _, dep := range strings.Fields(out) { //nolint:staticcheck // Fields で十分
		if dep == "github.com/kan/hokora/sdk" {
			continue
		}
		first, _, _ := strings.Cut(dep, "/")
		if strings.Contains(first, ".") {
			external = append(external, dep)
		}
	}

	if len(external) > 0 {
		t.Fatalf("the sdk pulls in non-standard-library packages: %s\n"+
			"it must depend on the standard library only (AGENTS.md)",
			strings.Join(external, ", "))
	}
}

// **パッケージの依存が空でも、module graph は空とは限らない。**
//
// AGENTS.md の教訓「部品の単体テストは配線を検証しない」がここに当たる。
// 上のテストは `go list -deps` すなわちパッケージ単位の依存しか見ておらず、
// go.mod に require が並んでいれば、SDK しか import していない利用側にも
// それが module graph として伝播する(実際、tool ディレクティブを root の
// go.mod に置いていた頃は利用側の `go list -m all` が 225 件になっていた)。
//
// SDK module 自身の build list が **自分 1 つだけ**であることを固定する。
// require を 1 つでも足すと落ちる。
func TestSDKModuleGraphContainsOnlyItself(t *testing.T) {
	t.Parallel()

	mods := strings.Fields(goList(t, "-m", "-f", "{{.Path}}", "all")) //nolint:staticcheck // Fields で十分
	if len(mods) != 1 || mods[0] != "github.com/kan/hokora/sdk" {
		t.Fatalf("the sdk module graph must contain only itself, got: %s\n"+
			"a require here propagates to every application that imports the sdk",
			strings.Join(mods, ", "))
	}
}

func goList(t *testing.T, args ...string) string {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	//nolint:gosec // G204: args はテスト内で固定した go list の引数である
	cmd := exec.CommandContext(t.Context(), "go", append([]string{"list"}, args...)...)

	// **GOWORK=off は必須である。** workspace(go.work)があると `go list -m all`
	// は workspace 全体の build list を返し、利用側が見る module graph とは
	// 別物になる。ここで測りたいのは **published module としての sdk** である。
	cmd.Env = append(cmd.Environ(), "GOWORK=off")

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v", strings.Join(args, " "), err)
	}

	return string(out)
}
