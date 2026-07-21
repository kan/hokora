GO         ?= go
BIN        ?= hokora
CLIENT_BIN ?= hokora-client
TIMEOUT    ?= 120s

.PHONY: all build build-client test vet fmt fmt-check lint vuln tidy clean

all: fmt-check vet lint test build

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

# lint / vuln のバージョンは go.mod の tool ディレクティブで固定する。
# 開発機と CI で同じ版が走り、モジュールキャッシュもそのまま効く。
lint:
	$(GO) tool golangci-lint run

vuln:
	$(GO) tool govulncheck ./...

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BIN) $(CLIENT_BIN)
