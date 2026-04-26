// Command websec101-cli is the standalone command-line interface for
// WebSec101. It can drive a remote websec101 server (default mode) or
// run a scan in-process via --standalone.
package main

import (
	"fmt"
	"os"

	"github.com/Jomar/websec101/cmd/websec101-cli/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "websec101-cli:", err)
		os.Exit(1)
	}
}
