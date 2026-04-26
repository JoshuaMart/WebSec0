//go:build tools
// +build tools

// This file pins the versions of code-generation tools so they are tracked
// in go.sum. They are not compiled into the binary.
//
// Run `go generate ./...` (or `make gen`) to regenerate the OpenAPI server
// and client.
package tools

import (
	_ "github.com/ogen-go/ogen/cmd/ogen"
)
