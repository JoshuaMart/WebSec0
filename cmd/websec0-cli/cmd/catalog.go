package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/cookies"
	scannerdns "github.com/JoshuaMart/websec0/internal/scanner/dns"
	"github.com/JoshuaMart/websec0/internal/scanner/email"
	"github.com/JoshuaMart/websec0/internal/scanner/headers"
	scannerhttp "github.com/JoshuaMart/websec0/internal/scanner/http"
	scannertls "github.com/JoshuaMart/websec0/internal/scanner/tls"
	"github.com/JoshuaMart/websec0/internal/scanner/wellknown"
	client "github.com/JoshuaMart/websec0/pkg/client"
)

func catalogCmd() *cobra.Command {
	var standalone bool
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "List every supported check (id, family, default severity)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var entries []checks.CheckMeta
			if standalone {
				r := checks.NewRegistry()
				wellknown.Register(r)
				scannertls.Register(r)
				headers.Register(r)
				cookies.Register(r)
				scannerdns.Register(r)
				email.Register(r)
				scannerhttp.Register(r)
				entries = r.Catalog()
			} else {
				ctx := context.Background()
				apiKey := globals.apiKey
				if apiKey == "" {
					apiKey = os.Getenv("WEBSEC0_API_KEY")
				}
				cli, err := client.NewClient(globals.server, client.WithClient(authClient(apiKey)))
				if err != nil {
					return fmt.Errorf("client: %w", err)
				}
				cks, err := cli.ListChecks(ctx)
				if err != nil {
					return fmt.Errorf("list checks: %w", err)
				}
				for _, c := range cks {
					entries = append(entries, checks.CheckMeta{
						ID:              c.ID,
						Family:          checks.Family(c.Family),
						DefaultSeverity: checks.Severity(c.DefaultSeverity),
						Title:           c.Title.Or(""),
						Description:     c.Description.Or(""),
					})
				}
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })

			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(entries)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-46s %-10s %s\n", "ID", "FAMILY", "SEVERITY")
			for _, e := range entries {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-46s %-10s %s\n",
					e.ID, e.Family, e.DefaultSeverity)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n%d checks\n", len(entries))
			return nil
		},
	}
	cmd.Flags().BoolVar(&standalone, "standalone", false,
		"Read the catalog from the in-process registry (no server)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output JSON")
	return cmd
}
