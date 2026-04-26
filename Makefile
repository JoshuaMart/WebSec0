.PHONY: build test test-race lint clean run gen help
.DEFAULT_GOAL := help

BIN_DIR    := bin
SERVER_BIN := $(BIN_DIR)/websec101
CLI_BIN    := $(BIN_DIR)/websec101-cli

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
              -X github.com/Jomar/websec101/internal/version.Version=$(VERSION) \
              -X github.com/Jomar/websec101/internal/version.Commit=$(COMMIT) \
              -X github.com/Jomar/websec101/internal/version.BuildDate=$(BUILD_DATE)

help:
	@echo "Targets:"
	@echo "  build      Build server and CLI binaries into $(BIN_DIR)/"
	@echo "  run        Run the server (go run ./cmd/websec101)"
	@echo "  test       Run unit tests"
	@echo "  test-race  Run tests with the race detector"
	@echo "  lint       Run golangci-lint"
	@echo "  gen        Run all go:generate directives"
	@echo "  clean      Remove build artefacts"

build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(SERVER_BIN) ./cmd/websec101
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(CLI_BIN)    ./cmd/websec101-cli

run:
	go run ./cmd/websec101

test:
	go test -count=1 ./...

test-race:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

gen:
	go generate ./...

clean:
	rm -rf $(BIN_DIR) dist/ coverage.txt coverage.html
