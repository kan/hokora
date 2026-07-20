GO      ?= go
BIN     ?= hokora
TIMEOUT ?= 120s

.PHONY: all build test vet fmt fmt-check lint vuln tidy clean

all: fmt-check vet lint test build

build:
	$(GO) build -o $(BIN) .

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
	rm -f $(BIN)
