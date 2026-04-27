// Command websec0-cli is the standalone command-line interface for
// WebSec101. It can drive a remote websec0 server (default mode) or
// run a scan in-process via --standalone.
package main

import (
	"fmt"
	"os"

	"github.com/JoshuaMart/websec0/cmd/websec0-cli/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "websec0-cli:", err)
		os.Exit(1)
	}
}
