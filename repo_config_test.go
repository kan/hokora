package main

import (
	"bufio"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// このファイルは、リポジトリの構成(go.mod の配置、Makefile、Dependabot、
// GitHub Actions のワークフロー)が AGENTS.md の規則と食い違っていないかを
// 検査する。どれも「構成を変えたのに、見張る仕組みの設定を動かし忘れる」
// 種類の誤りで、変更した本人のテストでは気付けない(AGENTS.md の教訓表:
// tools を別 module にしたとき dependabot.yml を動かし忘れ、更新 PR が
// 静かに止まった)。
//
// YAML のパーサは依存に足さない(AGENTS.md「依存の追加は原則禁止」)。
// 行単位で読むので、読めない形に書き換えたらテストが落ちる側に倒してある。

// goModDirs は、リポジトリ内の go.mod を持つディレクトリを、root を "." とした
// スラッシュ区切りの相対パスで返す。
//
// scripts/ は外部の repo の git subtree(scripts/tagpr)なので数えない。
// bin/ と dist/ はビルドの成果物、testdata/ は go コマンドも module として
// 扱わないので除く。
func goModDirs(t *testing.T) []string {
	t.Helper()

	skip := map[string]bool{".git": true, "scripts": true, "bin": true, "dist": true, "node_modules": true}

	var dirs []string
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && (skip[p] || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			dirs = append(dirs, filepath.ToSlash(filepath.Dir(p)))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the repository: %v", err)
	}
	slices.Sort(dirs)
	if !slices.Contains(dirs, ".") {
		t.Fatalf("root go.mod not found (found %v); run the test from the repository root", dirs)
	}
	return dirs
}

// makeVar は Makefile の `NAME := a b c` の値を空白で区切って返す。
// 継続行(末尾の `\`)は使っていない前提で、使われたら落とす。
func makeVar(t *testing.T, name string) []string {
	t.Helper()

	b, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\s*:?=(.*)$`)
	ms := re.FindAllStringSubmatch(string(b), -1)
	if len(ms) != 1 {
		t.Fatalf("Makefile: want exactly one assignment of %s, found %d", name, len(ms))
	}
	v := strings.TrimSpace(ms[0][1])
	if strings.HasSuffix(v, `\`) {
		t.Fatalf("Makefile: %s uses a line continuation; this test reads one line only", name)
	}
	return strings.Fields(v)
}

// dependabotDirs は .github/dependabot.yml の updates のうち、ecosystem が
// eco のものの directory を返す("/tools" → "tools"、"/" → ".")。
func dependabotDirs(t *testing.T, eco string) []string {
	t.Helper()

	f, err := os.Open(".github/dependabot.yml")
	if err != nil {
		t.Fatalf("open dependabot.yml: %v", err)
	}
	defer func() { _ = f.Close() }()

	itemRe := regexp.MustCompile(`^\s*-\s+package-ecosystem:\s*["']?([\w-]+)["']?\s*(#.*)?$`)
	dirRe := regexp.MustCompile(`^\s+directory:\s*["']?([^"'\s#]+)["']?\s*(#.*)?$`)

	var (
		dirs    []string
		current string // 直前の package-ecosystem
		hasDir  bool
	)
	flush := func() {
		if current == eco && !hasDir {
			t.Fatalf("dependabot.yml: a %s entry has no directory: line this test can read", eco)
		}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := itemRe.FindStringSubmatch(line); m != nil {
			flush()
			current, hasDir = m[1], false
			continue
		}
		if m := dirRe.FindStringSubmatch(line); m != nil && current != "" {
			if hasDir {
				t.Fatalf("dependabot.yml: two directory: lines in one %s entry", current)
			}
			hasDir = true
			if current == eco {
				d := strings.Trim(m[1], "/")
				if d == "" {
					d = "."
				}
				dirs = append(dirs, d)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read dependabot.yml: %v", err)
	}
	flush()
	slices.Sort(dirs)
	return dirs
}

// **go.mod を増やしたら、それを見張る設定にも足す**(AGENTS.md「root と tools は
// Go の最新に追随する」)。足し忘れても何も落ちず、その module の宣言や依存が
// 静かに古くなる。ここで、リポジトリにある go.mod と各設定の一覧を突き合わせる。
//
//   - Makefile の SUBMODULES: root 以外の全て(toolchain-check が root と比べる)
//   - Makefile の LATEST_GO_MODS: sdk 以外の全て(sdk の go 行は利用側への
//     最低要求で、最新に追随させない)
//   - dependabot.yml の gomod の directory: sdk 以外の全て(sdk は依存ゼロ)
//
// どれも「余計に入っている」も落とす。消した module を指したままの設定は、
// 検査が対象を失っていることを示すため。
func TestEveryGoModIsWatched(t *testing.T) {
	t.Parallel()

	all := goModDirs(t)
	without := func(drop ...string) []string {
		var out []string
		for _, d := range all {
			if !slices.Contains(drop, d) {
				out = append(out, d)
			}
		}
		return out
	}
	asGoModPaths := func(dirs []string) []string {
		out := make([]string, 0, len(dirs))
		for _, d := range dirs {
			out = append(out, path.Join(d, "go.mod"))
		}
		slices.Sort(out)
		return out
	}
	sorted := func(s []string) []string {
		s = slices.Clone(s)
		slices.Sort(s)
		return s
	}

	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{"Makefile SUBMODULES", sorted(makeVar(t, "SUBMODULES")), asGoModPaths(without("."))},
		{"Makefile LATEST_GO_MODS", sorted(makeVar(t, "LATEST_GO_MODS")), asGoModPaths(without("sdk"))},
		{"dependabot.yml gomod directories", dependabotDirs(t, "gomod"), without("sdk")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !slices.Equal(tt.got, tt.want) {
				t.Errorf("%s = %v, want %v (go.mod found in %v)\n"+
					"adding or removing a go.mod must update this setting too (AGENTS.md)",
					tt.name, tt.got, tt.want, all)
			}
		})
	}
}

// Actions の更新は Dependabot が uses: と actions.lock を一緒に作り直す
// (AGENTS.md「GitHub Actions」の表)。github-actions の項が消えると、
// action の更新 PR が静かに止まる。
func TestDependabotWatchesGitHubActions(t *testing.T) {
	t.Parallel()

	if got := dependabotDirs(t, "github-actions"); !slices.Equal(got, []string{"."}) {
		t.Errorf("dependabot.yml github-actions directories = %v, want [.]", got)
	}
}

// goModTools は go.mod の tool ディレクティブ(単一行とブロックの両方)を返す。
func goModTools(t *testing.T, file string) []string {
	t.Helper()

	b, err := os.ReadFile(file) //nolint:gosec // G304: テスト内で固定したリポジトリ内のパスである
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var (
		tools   []string
		inBlock bool
	)
	for line := range strings.Lines(string(b)) {
		line, _, _ = strings.Cut(line, "//")
		line = strings.TrimSpace(line)
		switch {
		case inBlock && line == ")":
			inBlock = false
		case inBlock && line != "":
			tools = append(tools, line)
		case line == "tool (":
			inBlock = true
		case strings.HasPrefix(line, "tool "):
			tools = append(tools, strings.TrimSpace(strings.TrimPrefix(line, "tool ")))
		}
	}
	slices.Sort(tools)
	return tools
}

// **goreleaser を tools/go.mod に入れない**(AGENTS.md「ツール依存」)。同じ
// module に置くと MVS で golangci-lint の依存版が引き上げられ、goreleaser の
// 更新が lint を動かす(一度入れて viper や prometheus の版が動いた)。
//
// tool ディレクティブだけでなく、require に goreleaser の module が現れない
// ことも見る(tool を消しても require が残れば build list は共有されたまま)。
func TestReleaseToolIsIsolatedFromLintTools(t *testing.T) {
	t.Parallel()

	const goreleaser = "github.com/goreleaser/goreleaser/v2"

	tests := []struct {
		file string
		want []string
	}{
		{"tools/go.mod", []string{
			"github.com/golangci/golangci-lint/v2/cmd/golangci-lint",
			"golang.org/x/vuln/cmd/govulncheck",
		}},
		{"tools/release/go.mod", []string{goreleaser}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			if got := goModTools(t, tt.file); !slices.Equal(got, tt.want) {
				t.Errorf("%s tools = %v, want %v\n"+
					"lint / vuln tools and goreleaser live in separate modules so that they "+
					"do not share a build list (AGENTS.md)", tt.file, got, tt.want)
			}
		})
	}

	b, err := os.ReadFile("tools/go.mod")
	if err != nil {
		t.Fatalf("read tools/go.mod: %v", err)
	}
	if strings.Contains(string(b), "github.com/goreleaser/goreleaser") {
		t.Errorf("tools/go.mod mentions goreleaser; it belongs in tools/release/go.mod only (AGENTS.md)")
	}
}

// workflowFiles は .github/workflows の *.yml / *.yaml を返す。
func workflowFiles(t *testing.T) []string {
	t.Helper()

	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(".github", "workflows", pat))
		if err != nil {
			t.Fatalf("glob workflows: %v", err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no workflow files found under .github/workflows")
	}
	slices.Sort(files)
	return files
}

// workflowLine は、ワークフローの 1 行と、それが属するジョブ(トップレベルなら "")。
type workflowLine struct {
	no   int
	job  string
	text string // 行全体(コメント行は除いてある)
}

// readWorkflow はワークフローを行単位で読み、各行にジョブ名を付ける。
// ジョブは `jobs:` の直下、インデント 2 のキーとして書かれている前提である
// (このリポジトリのワークフローは全てその形)。
func readWorkflow(t *testing.T, file string) []workflowLine {
	t.Helper()

	b, err := os.ReadFile(file) //nolint:gosec // G304: .github/workflows を Glob したリポジトリ内のパスである
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	jobKey := regexp.MustCompile(`^  ([\w-]+):\s*(#.*)?$`)

	var (
		lines  []workflowLine
		inJobs bool
		job    string
	)
	for i, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inJobs = strings.HasPrefix(line, "jobs:")
			job = ""
		} else if inJobs {
			if m := jobKey.FindStringSubmatch(line); m != nil {
				job = m[1]
			}
		}
		lines = append(lines, workflowLine{no: i + 1, job: job, text: line})
	}
	return lines
}

// **action は actions.lock でコミットに固定し、`uses:` は完全な版のタグで
// 書く。SHA を直接書かない**(AGENTS.md「GitHub Actions」)。lockfile の
// 照合は verify-lockfile.yml が CI で行う。ここでは push より前に、`@v7` の
// ような動くタグ、ブランチ、SHA の直書きを弾く。
func TestWorkflowUsesArePinnedByFullVersionTag(t *testing.T) {
	t.Parallel()

	usesRe := regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*["']?([^"'\s#]+)["']?`)
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@v\d+\.\d+\.\d+$`)
	// 例外: 別の repo の reusable workflow は actions.lock が固定しないので、
	// 完全な SHA で書く(AGENTS.md「GitHub Actions」「scripts/tagpr」)。
	// 許すのは subtree で取り込んだ kan/tagpr-scripts の workflow だけである。
	reusableBySHA := regexp.MustCompile(`^kan/tagpr-scripts/\.github/workflows/[\w.-]+\.ya?ml@[0-9a-f]{40}$`)

	for _, file := range workflowFiles(t) {
		var count int
		for _, l := range readWorkflow(t, file) {
			m := usesRe.FindStringSubmatch(l.text)
			if m == nil {
				continue
			}
			count++
			ref := m[1]
			if strings.HasPrefix(ref, "./") {
				continue // リポジトリ内の action / reusable workflow
			}
			if !pinned.MatchString(ref) && !reusableBySHA.MatchString(ref) {
				t.Errorf("%s:%d: uses: %s must name a full version tag (owner/repo@vX.Y.Z); "+
					"pin the commit in actions.lock, not in uses: (AGENTS.md)", file, l.no, ref)
			}
		}
		if count == 0 {
			// 読み取りの形が崩れて 0 件になったことを見逃さない
			// (全てのワークフローが少なくとも checkout を使う)。
			t.Errorf("%s: no uses: lines found; has the workflow format changed?", file)
		}
	}
}

// **書き込み権限は、要るジョブにだけ付ける。ワークフローの既定は
// `contents: read`。書き込み権限を持つジョブでビルドしない**
// (AGENTS.md「GitHub Actions」、「リリース手順」)。
//
// 書き込み権限の付与を allowlist で固定する。新しく付けるときは、ここに
// 足す(理由を説明できることを確かめる機会にする)。
func TestWorkflowWritePermissionsAreConfinedToAllowedJobs(t *testing.T) {
	t.Parallel()

	// file の basename → job → 許す write の scope
	allowed := map[string]map[string][]string{
		"release.yml": {
			"publish": {"contents"},
		},
		"tagpr.yml": {
			// actions: write は共通の workflow の release ジョブの宣言のため
			// (release-workflow が空なので、そのジョブは走らない)
			"tagpr":   {"contents", "pull-requests", "actions"},
			"sdk-tag": {"contents"},
			"release": {"actions"},
		},
	}
	// 書き込み権限を持つジョブで、Go の依存やツールを取ってきて走らせる
	// 兆候。ビルドは release.yml の build ジョブ(contents: read)だけで行う。
	buildSigns := []string{"actions/setup-go", "goreleaser", "make ", "go build", "go install", "go run", "go tool"}

	writeRe := regexp.MustCompile(`^\s*([\w-]+):\s*write\b`)
	topPerm := regexp.MustCompile(`^permissions:\s*(#.*)?$`)

	for _, file := range workflowFiles(t) {
		base := filepath.Base(file)
		lines := readWorkflow(t, file)

		// トップレベルの permissions を必ず書く。書かないと、リポジトリの
		// 設定次第で GITHUB_TOKEN が全 scope の書き込みを持つ。
		var hasTop bool
		for i, l := range lines {
			if topPerm.MatchString(l.text) {
				hasTop = true
				if i+1 >= len(lines) || strings.TrimSpace(lines[i+1].text) != "contents: read" {
					t.Errorf("%s:%d: top-level permissions must be exactly contents: read", file, l.no)
				}
			}
			if strings.Contains(l.text, "write-all") {
				t.Errorf("%s:%d: write-all is not allowed", file, l.no)
			}
		}
		if !hasTop {
			t.Errorf("%s: no top-level permissions: block (the default token may be read-write)", file)
		}

		writeJobs := map[string]bool{}
		for _, l := range lines {
			m := writeRe.FindStringSubmatch(l.text)
			if m == nil {
				continue
			}
			scope := m[1]
			if l.job == "" {
				t.Errorf("%s:%d: %s: write outside a job; grant write only to the job that needs it",
					file, l.no, scope)
				continue
			}
			if !slices.Contains(allowed[base][l.job], scope) {
				t.Errorf("%s:%d: job %q has %s: write, which is not in the allowlist of this test",
					file, l.no, l.job, scope)
			}
			writeJobs[l.job] = true
		}

		for _, l := range lines {
			if !writeJobs[l.job] {
				continue
			}
			for _, s := range buildSigns {
				if strings.Contains(l.text, s) {
					t.Errorf("%s:%d: job %q has a write permission and runs %q; "+
						"build only in a read-only job (AGENTS.md)", file, l.no, l.job, s)
				}
			}
		}
	}
}
