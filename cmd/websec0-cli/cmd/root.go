// Package cmd hosts the cobra command tree for websec0-cli.
package cmd

import (
	"github.com/spf13/cobra"
)

// Persistent flag values (read by every sub-command).
type rootOpts struct {
	server string // websec0 server URL for online mode
	apiKey string // optional bearer token (env: WEBSEC101_API_KEY)
}

var globals rootOpts

// Root returns the configured root command. main calls Execute.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "websec0-cli",
		Short: "Web security configuration scanner — CLI",
		Long: `websec0-cli runs WebSec101 scans against a target hostname.

By default it talks to a remote websec0 server (--server). Pass
--standalone to run the scan in-process without any server.

Examples:
  websec0-cli scan github.com --server https://websec0.example
  websec0-cli scan github.com --standalone --markdown
  websec0-cli scan badssl.com --standalone --fail-on critical,high
  websec0-cli catalog --standalone
  websec0-cli version`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&globals.server, "server",
		"http://localhost:8080", "websec0 server URL (online mode)")
	root.PersistentFlags().StringVar(&globals.apiKey, "api-key", "",
		"bearer token (env WEBSEC101_API_KEY)")

	root.AddCommand(scanCmd())
	root.AddCommand(reportCmd())
	root.AddCommand(catalogCmd())
	root.AddCommand(versionCmd())
	return root
}
