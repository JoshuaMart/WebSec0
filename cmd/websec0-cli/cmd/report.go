package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/JoshuaMart/websec0/internal/report"
	client "github.com/JoshuaMart/websec0/pkg/client"
)

func reportCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "report <scan-guid>",
		Short: "Re-render a stored scan from the server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("invalid GUID: %w", err)
			}
			ctx := context.Background()
			apiKey := globals.apiKey
			if apiKey == "" {
				apiKey = os.Getenv("WEBSEC0_API_KEY")
			}
			cli, err := client.NewClient(globals.server, client.WithClient(authClient(apiKey)))
			if err != nil {
				return fmt.Errorf("client: %w", err)
			}
			res, err := cli.GetScan(ctx, client.GetScanParams{GUID: id})
			if err != nil {
				return fmt.Errorf("get scan: %w", err)
			}
			scan, ok := res.(*client.Scan)
			if !ok {
				return fmt.Errorf("unexpected GetScan response: %T", res)
			}
			if scan.Status != client.ScanStatusCompleted {
				return fmt.Errorf("scan status is %q, expected completed", scan.Status)
			}
			rep := scanToReport(scan)
			return renderReport(cmd.OutOrStdout(), rep, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "human",
		"Output format: human|json|markdown|sarif")
	return cmd
}

// renderReport reuses the format dispatcher from scan.go (extracted to a
// named symbol so report.go can call it without duplicating logic).
func renderReport(w io.Writer, r *report.Report, format string) error {
	return render(w, r, format)
}
