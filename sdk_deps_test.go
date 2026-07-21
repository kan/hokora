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
	assertStdlibOnly(t, "./sdk", "the sdk", "github.com/kan/hokora/sdk")
}

// **クライアント専用バイナリ(cmd/hokora-client)は標準ライブラリ + sdk のみ**
// に依存する(AGENTS.md)。アプリホストに配るバイナリに、サーバー本体の依存
// (modernc.org/sqlite / argon2 等)を一切リンクさせないための不変条件である。
// サーバーとクライアントを分けた目的そのものなので、テストで固定する。
func TestClientBinaryDependsOnlyOnTheStandardLibraryAndSDK(t *testing.T) {
	t.Parallel()
	assertStdlibOnly(t, "./cmd/hokora-client", "the hokora-client binary",
		"github.com/kan/hokora/sdk", "github.com/kan/hokora/cmd/hokora-client")
}

// assertStdlibOnly は `go list -deps <pkg>` を走らせ、標準ライブラリと
// allowSelf に挙げたパッケージ以外のドメイン付き(サードパーティ)依存が
// 無いことを確かめる。
//
// 判定: サードパーティのパッケージはインポートパスの **先頭要素にドメイン
// (ドット)を持つ**(github.com/... 等)。標準ライブラリは持たない
// (net/http、crypto/internal/... 等)。
func assertStdlibOnly(t *testing.T, pkg, label string, allowSelf ...string) {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	//nolint:gosec // G204: pkg はテスト内で固定したパッケージパスである
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}

	allowed := make(map[string]bool, len(allowSelf))
	for _, s := range allowSelf {
		allowed[s] = true
	}

	var external []string
	for _, dep := range strings.Fields(string(out)) { //nolint:staticcheck // Fields で十分
		if allowed[dep] {
			continue
		}
		first, _, _ := strings.Cut(dep, "/")
		if strings.Contains(first, ".") {
			// 先頭要素にドットがある = ドメイン付き = サードパーティ。
			external = append(external, dep)
		}
	}

	if len(external) > 0 {
		t.Fatalf("%s pulls in non-standard-library packages: %s\n"+
			"it must depend on the standard library only (AGENTS.md)",
			label, strings.Join(external, ", "))
	}
}
