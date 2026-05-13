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
PNPM        ?= pnpm

BUNDLE_BUDGET_BYTES ?= 81920  # 80 KB gzip — see SPEC + TODO Phase 11

.PHONY: help build test lint frontend frontend-install bundle-size docker release-dry-run clean tidy

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

frontend-install: ## Install frontend dependencies (pnpm)
	cd web && $(PNPM) install

frontend: ## Build the Astro frontend and sync it into internal/frontend/dist
	cd web && $(PNPM) build
	rsync -a --delete --exclude='.keep' web/dist/ internal/frontend/dist/

bundle-size: ## Assert the Astro JS+CSS bundle stays under BUNDLE_BUDGET_BYTES gzipped
	@if [ ! -d web/dist/_astro ]; then \
	  echo "web/dist/_astro/ missing — run 'cd web && $(PNPM) build' first"; \
	  exit 1; \
	fi
	@size=$$(cat web/dist/_astro/*.js web/dist/_astro/*.css 2>/dev/null | gzip -9c | wc -c | tr -d ' '); \
	budget=$(BUNDLE_BUDGET_BYTES); \
	echo "bundle gzip: $$size bytes (budget $$budget)"; \
	if [ "$$size" -gt "$$budget" ]; then \
	  echo "Bundle over budget by $$((size - budget)) bytes"; \
	  exit 1; \
	fi

docker: ## Build the distroless Docker image
	docker build -t $(BINARY):$(VERSION) .

release-dry-run: ## Run goreleaser in snapshot mode (skips signing, publish and docker push)
	goreleaser release --snapshot --clean --skip=publish --skip=sign --skip=docker --skip=sbom

clean: ## Remove build artefacts (keeps internal/frontend/dist/.keep)
	rm -rf dist web/dist coverage.out coverage.html
	find internal/frontend/dist -mindepth 1 ! -name '.keep' -exec rm -rf {} + 2>/dev/null || true
