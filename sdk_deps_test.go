package main

import (
	"os/exec"
	"strings"
	"testing"
)

// **SDK は標準ライブラリのみに依存する**(AGENTS.md)。
//
// SDK を import するアプリに、サーバー本体の依存(modernc.org/sqlite 等)を
// 引き込ませないための不変条件である。`go list -deps ./sdk` を走らせ、
// 標準ライブラリと SDK 自身以外のパッケージが無いことを確かめる。
//
// 判定: サードパーティのパッケージはインポートパスの **先頭要素にドメイン
// (ドット)を持つ**(github.com/... 等)。標準ライブラリは持たない
// (net/http、crypto/internal/... 等)。SDK 自身だけは例外として許す。
func TestSDKDependsOnlyOnTheStandardLibrary(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "./sdk").Output()
	if err != nil {
		t.Fatalf("go list -deps ./sdk: %v", err)
	}

	const self = "github.com/kan/hokora/sdk"
	var external []string
	for _, pkg := range strings.Fields(string(out)) { //nolint:staticcheck // Fields で十分
		if pkg == self {
			continue
		}
		first, _, _ := strings.Cut(pkg, "/")
		if strings.Contains(first, ".") {
			// 先頭要素にドットがある = ドメイン付き = サードパーティ。
			external = append(external, pkg)
		}
	}

	if len(external) > 0 {
		t.Fatalf("the sdk pulls in non-standard-library packages: %s\n"+
			"the sdk must depend on the standard library only (AGENTS.md)",
			strings.Join(external, ", "))
	}
}
