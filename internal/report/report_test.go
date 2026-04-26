package report_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/report"
)

func sample(findings []checks.Finding) *report.Report {
	now := time.Date(2026, 4, 26, 18, 0, 0, 0, time.UTC)
	return report.Build(
		"abc-123", "example.com",
		now.Add(-30*time.Second), now,
		findings,
		report.BuildOptions{ScannerVersion: "0.1.0"},
	)
}

func TestPerfectScoreYieldsAPlus(t *testing.T) {
	t.Parallel()
	findings := []checks.Finding{
		{ID: "TLS-A", Family: checks.FamilyTLS, Severity: checks.SeverityHigh, Status: checks.StatusPass},
		{ID: "TLS-B", Family: checks.FamilyTLS, Severity: checks.SeverityMedium, Status: checks.StatusPass},
	}
	r := sample(findings)
	if r.Summary.Score != 100 || r.Summary.Grade != "A+" {
		t.Errorf("score=%d grade=%s, want 100/A+", r.Summary.Score, r.Summary.Grade)
	}
	if r.Summary.Counts.Passed != 2 {
		t.Errorf("Counts.Passed = %d", r.Summary.Counts.Passed)
	}
}

func TestPenaltiesApplied(t *testing.T) {
	t.Parallel()
	findings := []checks.Finding{
		{ID: "TLS-CRIT", Family: checks.FamilyTLS, Severity: checks.SeverityCritical, Status: checks.StatusFail},
		{ID: "HEADER-HIGH", Family: checks.FamilyHeaders, Severity: checks.SeverityHigh, Status: checks.StatusFail},
	}
	r := sample(findings)
	// Both families weighted (TLS 25, Headers 25 = 50). TLS scores
	// 100-25 = 75. Headers scores 100-10 = 90. Weighted: (75*25 + 90*25) / 50 = 82.
	if r.Summary.Score != 82 {
		t.Errorf("Score = %d, want 82", r.Summary.Score)
	}
	if r.Summary.Counts.Critical != 1 || r.Summary.Counts.High != 1 {
		t.Errorf("counts = %+v", r.Summary.Counts)
	}
}

func TestQuickWinsExtracted(t *testing.T) {
	t.Parallel()
	findings := []checks.Finding{
		{ID: "TLS-LOW", Family: checks.FamilyTLS, Severity: checks.SeverityLow, Status: checks.StatusFail},
		{ID: "HDR-MED", Family: checks.FamilyHeaders, Severity: checks.SeverityMedium, Status: checks.StatusFail, Title: "missing"},
		{ID: "DNS-INFO", Family: checks.FamilyDNS, Severity: checks.SeverityInfo, Status: checks.StatusFail},
		{ID: "EM-CRIT", Family: checks.FamilyEmail, Severity: checks.SeverityCritical, Status: checks.StatusFail},
	}
	r := sample(findings)
	if got := r.Summary.QuickWins; len(got) != 2 || got[0] != "EM-CRIT" || got[1] != "HDR-MED" {
		t.Errorf("QuickWins = %v, want [EM-CRIT HDR-MED]", got)
	}
	for _, f := range r.Findings {
		switch f.ID {
		case "EM-CRIT", "HDR-MED":
			if !f.IsQuickWin {
				t.Errorf("%s should be quick win", f.ID)
			}
		default:
			if f.IsQuickWin {
				t.Errorf("%s should not be quick win", f.ID)
			}
		}
	}
}

func TestSkippedAndPassedAreSegregated(t *testing.T) {
	t.Parallel()
	findings := []checks.Finding{
		{ID: "P1", Family: checks.FamilyTLS, Status: checks.StatusPass},
		{ID: "S1", Family: checks.FamilyEmail, Status: checks.StatusSkipped, Title: "no MX"},
	}
	r := sample(findings)
	if len(r.PassedChecks) != 1 || r.PassedChecks[0] != "P1" {
		t.Errorf("passed = %v", r.PassedChecks)
	}
	if len(r.SkippedChecks) != 1 || r.SkippedChecks[0].ID != "S1" {
		t.Errorf("skipped = %+v", r.SkippedChecks)
	}
}

func TestMarkdownContainsAllSections(t *testing.T) {
	t.Parallel()
	findings := []checks.Finding{
		{ID: "TLS-CERT-EXPIRED", Family: checks.FamilyTLS, Severity: checks.SeverityCritical, Status: checks.StatusFail, Title: "Cert expired"},
		{ID: "HEADER-CSP-MISSING", Family: checks.FamilyHeaders, Severity: checks.SeverityMedium, Status: checks.StatusFail, Title: "Missing CSP"},
		{ID: "DNS-DNSSEC-MISSING", Family: checks.FamilyDNS, Status: checks.StatusPass, Title: "Signed"},
	}
	r := sample(findings)
	md := report.Markdown(r)
	for _, want := range []string{
		"# WebSec101 Scan Report",
		"**Grade**:",
		"## Summary",
		"## Quick wins",
		"## Findings",
		"### TLS-CERT-EXPIRED",
		"### HEADER-CSP-MISSING",
		"## Passed checks",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown missing section: %q\n--- output:\n%s", want, md)
		}
	}
}

func TestSARIFShape(t *testing.T) {
	t.Parallel()
	findings := []checks.Finding{
		{ID: "TLS-CERT-EXPIRED", Family: checks.FamilyTLS, Severity: checks.SeverityCritical, Status: checks.StatusFail, Title: "Cert expired", Description: "expired"},
		{ID: "HEADER-CSP-MISSING", Family: checks.FamilyHeaders, Severity: checks.SeverityMedium, Status: checks.StatusFail, Title: "Missing CSP"},
		{ID: "DNS-AAAA-MISSING", Family: checks.FamilyDNS, Severity: checks.SeverityLow, Status: checks.StatusPass},
	}
	r := sample(findings)
	doc := report.ToSARIF(r)
	if doc.Version != "2.1.0" {
		t.Errorf("Version = %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("Runs = %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "WebSec101" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Errorf("results = %d, want 2 (pass excluded)", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}

	// Round-trip JSON to make sure the schema serialises cleanly.
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"$schema"`) || !strings.Contains(s, "sarif-schema-2.1.0") {
		t.Errorf("serialised doc missing schema URL\nfirst 400 chars: %s", s[:min(400, len(s))])
	}

	// Severity → level mapping.
	for _, res := range run.Results {
		switch res.RuleID {
		case "TLS-CERT-EXPIRED":
			if res.Level != "error" {
				t.Errorf("critical → level = %q, want error", res.Level)
			}
		case "HEADER-CSP-MISSING":
			if res.Level != "warning" {
				t.Errorf("medium → level = %q, want warning", res.Level)
			}
		}
	}
}
