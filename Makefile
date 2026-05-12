BINARY      := websec0
PKG         := github.com/JoshuaMart/websec0
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE        := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
               -X $(PKG)/internal/version.Version=$(VERSION) \
               -X $(PKG)/internal/version.Commit=$(COMMIT) \
               -X $(PKG)/internal/version.Date=$(DATE)

GO          ?= go
GOLANGCI    ?= golangci-lint
NPM         ?= npm

.PHONY: help build test lint frontend frontend-install docker clean tidy

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the websec0 binary into dist/
	@mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/$(BINARY)

test: ## Run all Go tests
	$(GO) test -race -count=1 ./...

lint: ## Run golangci-lint
	$(GOLANGCI) run ./...

tidy: ## go mod tidy
	$(GO) mod tidy

frontend-install: ## Install frontend dependencies
	cd web && $(NPM) install

frontend: ## Build the Astro frontend into web/dist
	cd web && $(NPM) run build

docker: ## Build the distroless Docker image
	docker build -t $(BINARY):$(VERSION) .

clean: ## Remove build artefacts
	rm -rf dist web/dist coverage.out coverage.html
