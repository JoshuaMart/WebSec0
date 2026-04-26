// Package client is the ogen-generated Go server + client for the
// WebSec101 API.
//
// It hosts both the server-side Handler interface (implemented internally
// by cmd/websec101) and the Client struct (importable by external Go
// programs). Request and response types are shared between both.
//
// Regenerate with `go generate ./...` (or `make gen`). All other files in
// this directory are produced by ogen and must not be edited by hand.
package client

//go:generate go run github.com/ogen-go/ogen/cmd/ogen --target . --package client --clean ../../api/openapi.yaml
