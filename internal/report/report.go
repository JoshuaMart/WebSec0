// Package report converts the raw findings of a completed scan into a
// scored Report (JSON envelope), a Markdown export, and a SARIF 2.1.0
// document.
package report

import (
	"time"

	"github.com/Jomar/websec101/internal/checks"
)

// SchemaVersion of the report envelope.
const SchemaVersion = "1.0"

// Report is the persisted JSON shape of a completed scan, wrapping the
// raw findings with grade / score / counts / quick-wins.
type Report struct {
	SchemaVersion string         `json:"schema_version"`
	Scan          ScanInfo       `json:"scan"`
	Summary       Summary        `json:"summary"`
	Findings      []FindingEntry `json:"findings"`
	PassedChecks  []string       `json:"passed_checks,omitempty"`
	SkippedChecks []SkippedCheck `json:"skipped_checks,omitempty"`
}

// ScanInfo captures the per-scan metadata.
type ScanInfo struct {
	ID              string    `json:"id"`
	Target          string    `json:"target"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at,omitempty"`
	DurationSeconds int       `json:"duration_seconds"`
	ScannerVersion  string    `json:"scanner_version"`
}

// Summary is the scored top-level overview rendered in Markdown summaries
// and SARIF run properties.
type Summary struct {
	Grade           string         `json:"grade"`
	Score           int            `json:"score"`
	ScoresPerFamily map[string]int `json:"scores_per_family"`
	Counts          Counts         `json:"counts"`
	QuickWins       []string       `json:"quick_wins"`
}

// Counts is the per-status / per-severity breakdown.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Passed   int `json:"passed"`
	Skipped  int `json:"skipped"`
	Errored  int `json:"errored"`
}

// FindingEntry mirrors checks.Finding but adds `IsQuickWin` derived at
// build time. Other Finding fields pass through verbatim.
type FindingEntry struct {
	ID          string               `json:"id"`
	Family      checks.Family        `json:"family"`
	Severity    checks.Severity      `json:"severity"`
	Status      checks.FindingStatus `json:"status"`
	Title       string               `json:"title,omitempty"`
	Description string               `json:"description,omitempty"`
	Evidence    map[string]any       `json:"evidence,omitempty"`
	Remediation map[string]any       `json:"remediation,omitempty"`
	IsQuickWin  bool                 `json:"is_quick_win,omitempty"`
}

// SkippedCheck is the (id, reason) pair surfaced under skipped_checks.
type SkippedCheck struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// BuildOptions parameterises Build.
type BuildOptions struct {
	ScannerVersion string
}

// Build produces a Report from the raw scan inputs. findings must be the
// full set produced by the runner (passed/skipped/errored included).
func Build(
	id, target string,
	startedAt time.Time,
	completedAt time.Time,
	findings []checks.Finding,
	opts BuildOptions,
) *Report {
	r := &Report{
		SchemaVersion: SchemaVersion,
		Scan: ScanInfo{
			ID:              id,
			Target:          target,
			StartedAt:       startedAt,
			CompletedAt:     completedAt,
			DurationSeconds: int(completedAt.Sub(startedAt).Seconds()),
			ScannerVersion:  opts.ScannerVersion,
		},
	}

	r.Findings = make([]FindingEntry, 0, len(findings))
	scoreInputs := make([]checks.Finding, 0, len(findings))

	for _, f := range findings {
		entry := FindingEntry{
			ID:          f.ID,
			Family:      f.Family,
			Severity:    f.Severity,
			Status:      f.Status,
			Title:       f.Title,
			Description: f.Description,
			Evidence:    f.Evidence,
			Remediation: f.Remediation,
		}

		//nolint:exhaustive // intentional partial switch

		switch f.Status {
		case checks.StatusPass:
			r.PassedChecks = append(r.PassedChecks, f.ID)
		case checks.StatusSkipped:
			r.SkippedChecks = append(r.SkippedChecks, SkippedCheck{
				ID:     f.ID,
				Reason: f.Title,
			})
		case checks.StatusFail, checks.StatusWarn, checks.StatusError:
			scoreInputs = append(scoreInputs, f)
			if isQuickWin(f) {
				entry.IsQuickWin = true
			}
		}

		r.Findings = append(r.Findings, entry)
	}

	r.Summary = computeSummary(findings, scoreInputs)
	return r
}

// isQuickWin reflects SPECIFICATIONS.md §6: a finding is a quick win
// when it's failing (or warning) at medium-or-higher severity. Most
// failures in our catalogue boil down to "set the right header /
// publish the right TXT record" — low effort, high impact.
func isQuickWin(f checks.Finding) bool {
	if f.Status != checks.StatusFail && f.Status != checks.StatusWarn {
		return false
	}
	//nolint:exhaustive // intentional partial switch
	switch f.Severity {
	case checks.SeverityMedium, checks.SeverityHigh, checks.SeverityCritical:
		return true
	}
	return false
}
