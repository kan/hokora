GO         ?= go
BIN        ?= hokora
CLIENT_BIN ?= hokora-client
TIMEOUT    ?= 120s
BINDIR     ?= bin

# root 以外の go.mod。go / toolchain の宣言が root からずれていないかを
# toolchain-check が検査する(**2 つ目の go.mod ができた時点で、片方だけ
# 古くなる経路ができる**)。
SUBMODULES := tools/go.mod

.PHONY: all build build-client test vet fmt fmt-check lint vuln tidy clean \
        toolchain-check

all: toolchain-check fmt-check vet lint test build

# go.mod の `toolchain` 行と、実際に走っている処理系の版が一致することを
# 確かめる。`go` 行は利用側への最低要求(1.26)であって patch を含まないため、
# **GOTOOLCHAIN=local かつ go1.26.0 の環境では宣言を満たしてしまい、既知の
# 脆弱性を持つ処理系でビルド・スキャンが通ってしまう。** 宣言(設定した)と
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
	rootgo="$$(sed -n 's/^go //p' go.mod)"; \
	for f in $(SUBMODULES); do \
		g="$$(sed -n 's/^go //p' $$f)"; t="$$(sed -n 's/^toolchain go//p' $$f)"; \
		if [ "$$g" != "$$rootgo" ] || [ "$$t" != "$$want" ]; then \
			echo "$$f の宣言が go.mod とずれている (go $$g / toolchain $$t)"; \
			echo "root は go $$rootgo / toolchain go$$want である"; exit 1; \
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
test:
	$(GO) test -race -timeout $(TIMEOUT) ./...

vet:
	$(GO) vet ./...

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
	$(BINDIR)/golangci-lint run

vuln: $(BINDIR)/govulncheck
	$(BINDIR)/govulncheck ./...

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BIN) $(CLIENT_BIN)
	rm -rf $(BINDIR)
