package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	ogenhttp "github.com/ogen-go/ogen/http"
	"github.com/spf13/cobra"

	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/report"
	"github.com/Jomar/websec101/internal/scanner"
	"github.com/Jomar/websec101/internal/scanner/cookies"
	scannerdns "github.com/Jomar/websec101/internal/scanner/dns"
	"github.com/Jomar/websec101/internal/scanner/email"
	"github.com/Jomar/websec101/internal/scanner/headers"
	scannerhttp "github.com/Jomar/websec101/internal/scanner/http"
	scannertls "github.com/Jomar/websec101/internal/scanner/tls"
	"github.com/Jomar/websec101/internal/scanner/wellknown"
	"github.com/Jomar/websec101/internal/version"
	client "github.com/Jomar/websec101/pkg/client"
)

type scanOpts struct {
	standalone  bool
	formatJSON  bool
	formatMD    bool
	formatSARIF bool
	failOn      string
	wait        int
}

func scanCmd() *cobra.Command {
	var opts scanOpts
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan a target hostname for security misconfigurations",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(opts.wait+30)*time.Second)
			defer cancel()
			if cmd.Context() == nil {
				ctx, cancel = context.WithTimeout(context.Background(), time.Duration(opts.wait+30)*time.Second)
				defer cancel()
			}

			format := pickFormat(opts)

			var rep *report.Report
			var err error
			if opts.standalone {
				rep, err = runStandalone(ctx, target, opts.wait)
			} else {
				rep, err = runOnline(ctx, target, opts.wait)
			}
			if err != nil {
				return err
			}

			if err := render(cmd.OutOrStdout(), rep, format); err != nil {
				return err
			}

			if opts.failOn != "" {
				if hit := matchFailOn(rep, parseSevList(opts.failOn)); hit != "" {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "fail-on: %s triggered exit\n", hit)
					os.Exit(2)
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.standalone, "standalone", false,
		"Run the scan in-process (no server)")
	cmd.Flags().BoolVar(&opts.formatJSON, "json", false, "Output the full JSON report")
	cmd.Flags().BoolVar(&opts.formatMD, "markdown", false, "Output Markdown")
	cmd.Flags().BoolVar(&opts.formatSARIF, "sarif", false, "Output SARIF 2.1.0")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "",
		"Comma-separated severities (critical,high,medium,low,info) — exit 2 on match")
	cmd.Flags().IntVar(&opts.wait, "wait", 120, "Max seconds to wait for completion")
	return cmd
}

// pickFormat selects the requested output format. Defaults to a human
// summary when no flag is set.
func pickFormat(o scanOpts) string {
	switch {
	case o.formatJSON:
		return "json"
	case o.formatMD:
		return "markdown"
	case o.formatSARIF:
		return "sarif"
	default:
		return "human"
	}
}

// runStandalone builds a private registry+manager, runs the scan, and
// returns the rendered Report.
func runStandalone(ctx context.Context, hostname string, waitSec int) (*report.Report, error) {
	tgt, err := checks.NewTarget(hostname, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	r := checks.NewRegistry()
	wellknown.Register(r)
	scannertls.Register(r)
	headers.Register(r)
	cookies.Register(r)
	scannerdns.Register(r)
	email.Register(r)
	scannerhttp.Register(r)

	runner := scanner.NewRunner(r, scanner.RunnerConfig{
		MaxConcurrent:   10,
		PerCheckTimeout: 8 * time.Second,
	})

	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(waitSec)*time.Second)
	defer cancel()

	started := time.Now().UTC()
	findings, err := runner.Run(scanCtx, tgt, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	completed := time.Now().UTC()

	rep := report.Build("standalone", hostname, started, completed, findings,
		report.BuildOptions{ScannerVersion: version.Version})
	return rep, nil
}

// runOnline POSTs a scan to --server, waits for completion via the
// `wait_seconds` option, and assembles a Report from the resulting
// scan body.
func runOnline(ctx context.Context, hostname string, waitSec int) (*report.Report, error) {
	apiKey := globals.apiKey
	if apiKey == "" {
		apiKey = os.Getenv("WEBSEC101_API_KEY")
	}
	cli, err := client.NewClient(globals.server, client.WithClient(authClient(apiKey)))
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}

	res, err := cli.CreateScan(ctx, &client.ScanRequest{
		Target: hostname,
		Options: client.NewOptScanOptions(client.ScanOptions{
			WaitSeconds: client.NewOptInt(waitSec),
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("create scan: %w", err)
	}
	created, ok := res.(*client.ScanCreatedHeaders)
	if !ok {
		return nil, fmt.Errorf("unexpected create response: %T", res)
	}
	id := created.Response.ID

	scan, err := pollUntilComplete(ctx, cli, id, time.Duration(waitSec)*time.Second)
	if err != nil {
		return nil, err
	}
	return scanToReport(scan), nil
}

// pollUntilComplete blocks until scan.status is terminal or deadline.
func pollUntilComplete(ctx context.Context, cli *client.Client, id uuid.UUID, deadline time.Duration) (*client.Scan, error) {
	tCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		res, err := cli.GetScan(tCtx, client.GetScanParams{GUID: id})
		if err != nil {
			return nil, err
		}
		scan, ok := res.(*client.Scan)
		if !ok {
			return nil, fmt.Errorf("unexpected GetScan response: %T", res)
		}
		switch scan.Status { //nolint:exhaustive // queued/running fall through to the poll loop
		case client.ScanStatusCompleted, client.ScanStatusFailed:
			return scan, nil
		}
		select {
		case <-tCtx.Done():
			return scan, fmt.Errorf("scan did not complete within %s", deadline)
		case <-tick.C:
		}
	}
}

// scanToReport converts the API-side Scan response into our local Report
// type so the same renderers can be reused.
func scanToReport(s *client.Scan) *report.Report {
	findings := make([]checks.Finding, 0, len(s.Findings))
	for _, f := range s.Findings {
		findings = append(findings, checks.Finding{
			ID:       f.ID,
			Family:   checks.Family(f.Family),
			Severity: checks.Severity(f.Severity),
			Status:   checks.FindingStatus(f.Status),
			Title:    f.Title.Or(""),
		})
	}
	completed := s.StartedAt
	if v, ok := s.CompletedAt.Get(); ok {
		completed = v
	}
	return report.Build(s.ID.String(), s.Target, s.StartedAt, completed, findings,
		report.BuildOptions{ScannerVersion: version.Version})
}

// authClient adds an Authorization: Bearer header to every outbound
// request when an API key is provided. ogen's WithClient drops nil so
// passing it back from here lets the default transport win.
func authClient(apiKey string) ogenhttp.Client {
	if apiKey == "" {
		return nil
	}
	return &bearerTransport{token: apiKey, base: http.DefaultClient}
}

type bearerTransport struct {
	token string
	base  *http.Client
}

func (b *bearerTransport) Do(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.token)
	//nolint:gosec // user-supplied --server URL is the intended target
	return b.base.Do(r)
}

// render writes the Report in the requested format.
func render(w io.Writer, r *report.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "markdown":
		_, err := io.WriteString(w, report.Markdown(r))
		return err
	case "sarif":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report.ToSARIF(r))
	default:
		return renderHuman(w, r)
	}
}

// renderHuman is the default short summary.
func renderHuman(w io.Writer, r *report.Report) error {
	_, _ = fmt.Fprintf(w, "Target:  %s\n", r.Scan.Target)
	_, _ = fmt.Fprintf(w, "Grade:   %s (%d/100)\n", r.Summary.Grade, r.Summary.Score)
	_, _ = fmt.Fprintf(w, "Counts:  critical=%d high=%d medium=%d low=%d info=%d  pass=%d skip=%d err=%d\n",
		r.Summary.Counts.Critical, r.Summary.Counts.High, r.Summary.Counts.Medium,
		r.Summary.Counts.Low, r.Summary.Counts.Info,
		r.Summary.Counts.Passed, r.Summary.Counts.Skipped, r.Summary.Counts.Errored)
	if len(r.Summary.QuickWins) > 0 {
		_, _ = fmt.Fprintf(w, "\nQuick wins (%d):\n", len(r.Summary.QuickWins))
		for _, id := range r.Summary.QuickWins {
			_, _ = fmt.Fprintf(w, "  - %s\n", id)
		}
	}
	return nil
}

// matchFailOn returns the first finding ID whose severity is in the set,
// or "" when nothing matches. Only fail/warn statuses are considered.
func matchFailOn(r *report.Report, sevs map[string]struct{}) string {
	for _, f := range r.Findings {
		if f.Status != checks.StatusFail && f.Status != checks.StatusWarn {
			continue
		}
		if _, ok := sevs[strings.ToLower(string(f.Severity))]; ok {
			return f.ID
		}
	}
	return ""
}

func parseSevList(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

// silenceSlog redirects slog output during CLI operations so the manager's
// logs don't interleave with the human report. (Currently unused — the
// standalone path uses the runner directly without a manager.)
func silenceSlog() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// (silenceSlog kept to satisfy linter on potential future use)
var _ = silenceSlog
