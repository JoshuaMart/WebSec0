.PHONY: build build-all web test test-race test-e2e test-e2e-fixture lint clean run gen docs help
.DEFAULT_GOAL := help

BIN_DIR    := bin
SERVER_BIN := $(BIN_DIR)/websec0
CLI_BIN    := $(BIN_DIR)/websec0-cli
WEB_DIR    := web

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
              -X github.com/JoshuaMart/websec0/internal/version.Version=$(VERSION) \
              -X github.com/JoshuaMart/websec0/internal/version.Commit=$(COMMIT) \
              -X github.com/JoshuaMart/websec0/internal/version.BuildDate=$(BUILD_DATE)

help:
	@echo "Targets:"
	@echo "  build      Build server and CLI binaries (requires web already built)"
	@echo "  build-all  Build frontend then Go binaries"
	@echo "  web        Install frontend deps and build Astro into internal/webfs/dist/"
	@echo "  web-dev    Start Astro dev server (proxy to :8080)"
	@echo "  run        Run the server (go run ./cmd/websec0)"
	@echo "  test       Run unit tests"
	@echo "  test-race  Run tests with the race detector"
	@echo "  test-e2e   Run full-orchestrator E2E suites (badssl + reference, needs internet)"
	@echo "  test-e2e-fixture  Bring up the legacy fixture, run the gated E2E test, tear down"
	@echo "  lint       Run golangci-lint"
	@echo "  gen        Run all go:generate directives"
	@echo "  docs       Regenerate per-check docs under docs/checks/"
	@echo "  clean      Remove build artefacts"

build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(SERVER_BIN) ./cmd/websec0
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(CLI_BIN)    ./cmd/websec0-cli

build-all: web build

web:
	cd $(WEB_DIR) && pnpm install --frozen-lockfile && pnpm build

web-dev:
	cd $(WEB_DIR) && pnpm dev

run:
	go run ./cmd/websec0

test:
	go test -count=1 ./...

test-race:
	go test -race -count=1 ./...

test-e2e:
	go test -tags e2e -count=1 -timeout 10m -v ./tests/e2e/...

test-e2e-fixture:
	$(MAKE) -C tests/e2e/legacy-fixture up
	WEBSEC0_LEGACY_FIXTURE_HOST=localhost:18443 \
	  go test -tags e2e -count=1 -v -run TestE2E_LegacyFixture ./tests/e2e/...; \
	  status=$$?; \
	  $(MAKE) -C tests/e2e/legacy-fixture down; \
	  exit $$status

lint:
	golangci-lint run ./...

gen:
	cp -f api/openapi.yaml internal/api/spec/openapi.yaml
	go generate ./...

docs:
	./scripts/gen-checks-docs.sh

clean:
	rm -rf $(BIN_DIR) internal/webfs/dist coverage.txt coverage.html
	cd $(WEB_DIR) && rm -rf node_modules .astro
