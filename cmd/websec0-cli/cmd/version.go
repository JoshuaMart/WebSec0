package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JoshuaMart/websec0/internal/version"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print scanner build metadata",
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"websec0-cli %s (commit %s, built %s)\n",
				info.Version, info.Commit, info.BuildDate)
			return nil
		},
	}
}
