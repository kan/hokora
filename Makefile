GO         ?= go
BIN        ?= hokora
CLIENT_BIN ?= hokora-client
TIMEOUT    ?= 5m
BINDIR     ?= bin

# root 以外の go.mod。toolchain の宣言が root からずれていないかを
# toolchain-check が検査する(**2 つ目の go.mod ができた時点で、片方だけ
# 古くなる経路ができる**)。go 行は利用側への最低要求なので、sdk のように
# 意図的に低く宣言してよい(root より高いのは許さない)。
SUBMODULES := tools/go.mod sdk/go.mod

# パッケージを持つ module。sdk は別 module なので、root の ./... には
# 入らない。**test / vet / lint を root だけで回すと sdk が素通しになる。**
MODULES := . sdk

.PHONY: all build build-client test vet fmt fmt-check lint vuln tidy clean \
        toolchain-check toolchain-latest docs-check

all: toolchain-check fmt-check docs-check vet lint test build

# docs/ は GitHub Pages(Jekyll)の公開元である。front matter の無い Markdown も
# 全てページになり、**本文は Liquid として解釈される。** 波括弧 2 つの式は
# 黙って空になり(Go のテンプレートの例を書くと、その部分だけ消える)、
# 波括弧とパーセントのタグは未定義ならサイトのビルドごと失敗する。
# どちらも push した後でしか分からないので、ここで弾く。
docs-check:
	@out="$$(grep -rnE '\{\{|\{%' --include='*.md' docs || true)"; \
	if [ -n "$$out" ]; then \
		echo "docs/ の Markdown に Liquid として解釈される記法がある (GitHub Pages で消えるか、ビルドが落ちる):"; \
		echo "$$out"; exit 1; \
	fi

# go.mod の `toolchain` 行と、実際に走っている処理系の版が一致することを
# 確かめる。`go` 行は minor までの宣言であって patch を含まないため、
# **GOTOOLCHAIN=local かつその minor の古い patch(x.y.0 等)の環境では宣言を
# 満たしてしまい、既知の脆弱性を持つ処理系でビルド・スキャンが通ってしまう。** 宣言(設定した)と
# 実行(効いている)を突き合わせてそこを塞ぐ。CI も同じターゲットを呼ぶ。
toolchain-check:
	@want="$$(sed -n 's/^toolchain go//p' go.mod)"; \
	got="$$($(GO) version | awk '{print $$3}' | sed 's/^go//')"; \
	echo "go.mod toolchain=$$want  running=$$got"; \
	if [ -z "$$want" ]; then \
		echo "go.mod に toolchain 行がない (AGENTS.md 技術スタック節を参照)"; exit 1; \
	fi; \
	if [ "$$want" != "$$got" ]; then \
		echo "toolchain mismatch: go.mod は go$$want を宣言しているが go$$got で走っている"; \
		echo "GOTOOLCHAIN=auto (既定) で実行するか、go$$want を入れること"; exit 1; \
	fi; \
	rootgo="$$(sed -n 's/^go //p' go.mod | cut -d. -f1,2)"; \
	for f in $(SUBMODULES); do \
		g="$$(sed -n 's/^go //p' $$f | cut -d. -f1,2)"; t="$$(sed -n 's/^toolchain go//p' $$f)"; \
		if [ "$$t" != "$$want" ]; then \
			echo "$$f の toolchain が go.mod とずれている (go$$t / root は go$$want)"; \
			exit 1; \
		fi; \
		if [ "$$(printf '%s\n%s\n' "$$g" "$$rootgo" | sort -V | head -1)" != "$$g" ]; then \
			echo "$$f の go 行 ($$g) が root ($$rootgo) より新しい"; \
			echo "go 行は利用側への最低要求である。root を超えて上げない"; exit 1; \
		fi; \
	done
# go 行の比較は minor までで行う。依存が `go 1.27.0` を要求すると go コマンドが
# go 行を patch 付きへ書き換えるが、`sort -V` は `1.27` < `1.27.0` と並べるため、
# そのまま比べると tools だけ書き換わった時点で「root より新しい」と誤判定する。

# go.mod の宣言が、公開されている最新の安定版 Go に追随していることを確かめる
# (AGENTS.md「root と tools は Go の最新に追随する」)。
#
# **toolchain-check は「宣言と実行の一致」しか見ない。宣言そのものが古いことは
# 検出しない。** Dependabot も toolchain 行を上げないため、go1.26.6 のまま
# 1.26.9 と 1.27 系を見送り、定期の govulncheck が赤くなるまで気付けなかった。
# 変更起因ではないので `all` には入れず、toolchain.yml の定期実行から呼ぶ。
#
# 検査するのは toolchain 行(全 module で共通。toolchain-check が揃える)と、
# root / tools の go 行の minor。sdk の go 行は利用側への最低要求なので見ない。
# 取得に失敗したら通さない(検査できていないのに緑にしない)。
LATEST_GO_MODS := go.mod tools/go.mod

toolchain-latest:
	@latest="$$(curl -fsSL --retry 3 --retry-all-errors 'https://go.dev/VERSION?m=text' \
		| sed -n '1s/^go//p')"; \
	if [ -z "$$latest" ]; then \
		echo "最新の Go の版を取得できなかった (https://go.dev/VERSION?m=text)"; exit 1; \
	fi; \
	want="$$(sed -n 's/^toolchain go//p' go.mod)"; \
	echo "go.mod toolchain=$$want  latest=$$latest"; \
	if [ "$$want" != "$$latest" ]; then \
		echo "toolchain が古い: go.mod は go$$want、最新の安定版は go$$latest"; \
		echo "全ての go.mod の toolchain 行を上げること (AGENTS.md 技術スタック節)"; exit 1; \
	fi; \
	minor="$$(echo "$$latest" | cut -d. -f1,2)"; \
	for f in $(LATEST_GO_MODS); do \
		g="$$(sed -n 's/^go //p' $$f | cut -d. -f1,2)"; \
		if [ "$$g" != "$$minor" ]; then \
			echo "$$f の go 行 ($$g) が最新の minor ($$minor) とずれている"; exit 1; \
		fi; \
	done

# サーバー本体(hokora)とクライアント専用バイナリ(hokora-client)の両方を
# ビルドする。クライアントは標準ライブラリ + sdk のみに依存し、サーバーの
# sqlite / argon2 を積まない(sdk_deps_test.go で不変条件を検査)。
build: build-client
	$(GO) build -o $(BIN) .

build-client:
	$(GO) build -o $(CLIENT_BIN) ./cmd/hokora-client

# 並行制御のバグは race detector なしでは見えない。既定で -race を付ける。
# 暴走したテストで環境ごと固まらないよう -timeout を必ず指定する。
#
# **TIMEOUT は「暴走の検出」のためのものであり、遅いマシンの足切りではない。**
# -race を付けた本体のテストは実測で 2 分を超えることがあり、既定を 120s に
# していた頃は変更と無関係に落ちた。テストは増える一方なので余裕を持たせる。
test:
	@for m in $(MODULES); do \
		echo "==> go test ($$m)"; \
		$(GO) test -C $$m -race -timeout $(TIMEOUT) ./... || exit 1; \
	done

vet:
	@for m in $(MODULES); do $(GO) vet -C $$m ./... || exit 1; done

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# lint / vuln のバージョンは tools/go.mod の tool ディレクティブで固定する。
# 開発機と CI で同じ版が走る。
#
# **ツールを root ではなく tools/ の別 module に置いているのは、成果物に
# リンクされない依存を利用側の module graph から切り離すためである。**
# root に置くとツールの indirect(200 module 超)が root の go.mod に並び、
# SDK しか import していない利用側にも伝播する。tools module からバイナリを
# ビルドして repo root で実行することで、スキャン対象は root module のまま
# にする(`go tool -C tools` では ./... が tools 側に解決されてしまう)。
$(BINDIR)/golangci-lint: tools/go.mod tools/go.sum
	$(GO) build -C tools -o ../$(BINDIR)/golangci-lint \
		github.com/golangci/golangci-lint/v2/cmd/golangci-lint

$(BINDIR)/govulncheck: tools/go.mod tools/go.sum
	$(GO) build -C tools -o ../$(BINDIR)/govulncheck \
		golang.org/x/vuln/cmd/govulncheck

lint: $(BINDIR)/golangci-lint
	@for m in $(MODULES); do \
		echo "==> golangci-lint ($$m)"; \
		(cd $$m && $(abspath $(BINDIR))/golangci-lint run) || exit 1; \
	done

vuln: $(BINDIR)/govulncheck
	$(BINDIR)/govulncheck ./...

tidy:
	@for m in $(MODULES) tools; do $(GO) mod tidy -C $$m || exit 1; done

clean:
	rm -f $(BIN) $(CLIENT_BIN)
	rm -rf $(BINDIR)
