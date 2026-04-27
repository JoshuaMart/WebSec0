package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// Markdown renders a Report as the human-and-agent-friendly Markdown
// described in SPECIFICATIONS.md §6.5.
func Markdown(r *Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# WebSec101 Scan Report — %s\n\n", r.Scan.Target)
	fmt.Fprintf(&b, "**Date**: %s  \n", r.Scan.StartedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "**Grade**: %s (%d/100)  \n", r.Summary.Grade, r.Summary.Score)
	if r.Scan.DurationSeconds > 0 {
		fmt.Fprintf(&b, "**Duration**: %ds  \n", r.Scan.DurationSeconds)
	}
	fmt.Fprintf(&b, "**Scanner**: WebSec101 %s\n\n", r.Scan.ScannerVersion)

	// Summary table.
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n|----------|------:|\n")
	fmt.Fprintf(&b, "| Critical | %d |\n", r.Summary.Counts.Critical)
	fmt.Fprintf(&b, "| High     | %d |\n", r.Summary.Counts.High)
	fmt.Fprintf(&b, "| Medium   | %d |\n", r.Summary.Counts.Medium)
	fmt.Fprintf(&b, "| Low      | %d |\n", r.Summary.Counts.Low)
	fmt.Fprintf(&b, "| Info     | %d |\n", r.Summary.Counts.Info)
	fmt.Fprintf(&b, "| Passed   | %d |\n", r.Summary.Counts.Passed)
	if r.Summary.Counts.Skipped > 0 {
		fmt.Fprintf(&b, "| Skipped  | %d |\n", r.Summary.Counts.Skipped)
	}
	if r.Summary.Counts.Errored > 0 {
		fmt.Fprintf(&b, "| Errored  | %d |\n", r.Summary.Counts.Errored)
	}
	b.WriteString("\n")

	// Per-family scores.
	if len(r.Summary.ScoresPerFamily) > 0 {
		b.WriteString("### Scores by family\n\n| Family | Score |\n|--------|------:|\n")
		fams := make([]string, 0, len(r.Summary.ScoresPerFamily))
		for k := range r.Summary.ScoresPerFamily {
			fams = append(fams, k)
		}
		sort.Strings(fams)
		for _, k := range fams {
			fmt.Fprintf(&b, "| %s | %d |\n", k, r.Summary.ScoresPerFamily[k])
		}
		b.WriteString("\n")
	}

	// Quick wins.
	if len(r.Summary.QuickWins) > 0 {
		b.WriteString("## Quick wins\n\n")
		b.WriteString("The following findings are low-effort, high-impact:\n\n")
		quickFindings := map[string]FindingEntry{}
		for _, f := range r.Findings {
			quickFindings[f.ID] = f
		}
		for i, id := range r.Summary.QuickWins {
			f := quickFindings[id]
			title := f.Title
			if title == "" {
				title = id
			}
			fmt.Fprintf(&b, "%d. **%s** — %s\n", i+1, id, title)
		}
		b.WriteString("\n")
	}

	// Findings (failures + warns + errors only — passes go in the
	// passed_checks footer to keep the report scannable).
	var negatives []FindingEntry
	for _, f := range r.Findings {
		//nolint:exhaustive // intentional partial switch
		switch f.Status {
		case checks.StatusFail, checks.StatusWarn, checks.StatusError:
			negatives = append(negatives, f)
		}
	}
	sort.SliceStable(negatives, func(i, j int) bool {
		return severityRank(negatives[i].Severity) > severityRank(negatives[j].Severity)
	})

	if len(negatives) > 0 {
		b.WriteString("## Findings\n\n")
		for _, f := range negatives {
			renderFinding(&b, f)
			b.WriteString("\n---\n\n")
		}
	}

	// Footer.
	if len(r.PassedChecks) > 0 {
		fmt.Fprintf(&b, "## Passed checks (%d)\n\n", len(r.PassedChecks))
		ids := append([]string(nil), r.PassedChecks...)
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(&b, "- %s\n", id)
		}
		b.WriteString("\n")
	}
	if len(r.SkippedChecks) > 0 {
		fmt.Fprintf(&b, "## Skipped checks (%d)\n\n", len(r.SkippedChecks))
		for _, s := range r.SkippedChecks {
			fmt.Fprintf(&b, "- %s — %s\n", s.ID, s.Reason)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("> **Disclaimer**: WebSec0 is a passive configuration scanner. " +
		"Findings are based on observed configuration and known best practices; " +
		"they are not a substitute for a full security assessment. " +
		"WebSec0 makes no guarantee regarding the absence of vulnerabilities not covered by its checks. " +
		"The user is responsible for ensuring they have authorization to scan the target.\n")

	return b.String()
}

func renderFinding(b *strings.Builder, f FindingEntry) {
	title := f.Title
	if title == "" {
		title = f.ID
	}
	fmt.Fprintf(b, "### %s — %s\n", f.ID, title)
	quick := "no"
	if f.IsQuickWin {
		quick = "yes"
	}
	fmt.Fprintf(b, "**Severity**: %s · **Status**: %s · **Quick win**: %s\n\n",
		f.Severity, f.Status, quick)
	if f.Description != "" {
		fmt.Fprintf(b, "%s\n\n", f.Description)
	}
	if len(f.Evidence) > 0 {
		b.WriteString("**Evidence**:\n\n```json\n")
		// stable order for reproducibility
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(b, "  %q: %v,\n", k, f.Evidence[k])
		}
		b.WriteString("```\n\n")
	}
}

func severityRank(s checks.Severity) int {
	switch s {
	case checks.SeverityCritical:
		return 5
	case checks.SeverityHigh:
		return 4
	case checks.SeverityMedium:
		return 3
	case checks.SeverityLow:
		return 2
	case checks.SeverityInfo:
		return 1
	}
	return 0
}
