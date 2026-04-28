package report

import (
	"github.com/JoshuaMart/websec0/internal/checks"
)

// SARIF is a minimal subset of the SARIF 2.1.0 schema sufficient for
// GitHub Code Scanning ingestion (oasis-tcs/sarif-spec).
type SARIF struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool      `json:"tool"`
	Results     []SARIFResult  `json:"results"`
	Invocations []SARIFInvoc   `json:"invocations,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name,omitempty"`
	ShortDescription     SARIFText               `json:"shortDescription,omitempty"`
	FullDescription      SARIFText               `json:"fullDescription,omitempty"`
	DefaultConfiguration *SARIFRuleConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any          `json:"properties,omitempty"`
}

type SARIFRuleConfiguration struct {
	Level string `json:"level"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID     string         `json:"ruleId"`
	Level      string         `json:"level"`
	Message    SARIFText      `json:"message"`
	Properties map[string]any `json:"properties,omitempty"`
	Locations  []SARIFLoc     `json:"locations,omitempty"`
}

type SARIFLoc struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFInvoc struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// ToSARIF renders r as a SARIF 2.1.0 document. Failing/warning/erroring
// findings become results; passes and skipped are intentionally dropped
// (SARIF readers expect issues, not affirmations).
func ToSARIF(r *Report) *SARIF {
	doc := &SARIF{
		Schema:  sarifSchema,
		Version: "2.1.0",
	}
	run := SARIFRun{
		Tool: SARIFTool{Driver: SARIFDriver{
			Name:           "WebSec0",
			Version:        r.Scan.ScannerVersion,
			InformationURI: "https://websec0.example",
		}},
		Properties: map[string]any{
			"target": r.Scan.Target,
			"grade":  r.Summary.Grade,
			"score":  r.Summary.Score,
		},
	}

	// One rule per distinct finding ID — keeps the schema GitHub-friendly.
	rules := map[string]SARIFRule{}
	targetURI := "https://" + r.Scan.Target + "/"

	for _, f := range r.Findings {
		switch f.Status {
		case checks.StatusFail, checks.StatusWarn, checks.StatusError:
		default:
			continue
		}
		level := levelFromSeverity(f.Severity)

		if _, ok := rules[f.ID]; !ok {
			rules[f.ID] = SARIFRule{
				ID:               f.ID,
				Name:             ruleName(f.ID),
				ShortDescription: SARIFText{Text: defaultText(f.Title, f.ID)},
				FullDescription:  SARIFText{Text: defaultText(f.Description, f.Title)},
				DefaultConfiguration: &SARIFRuleConfiguration{
					Level: level,
				},
				Properties: map[string]any{
					"family":           string(f.Family),
					"default_severity": string(f.Severity),
				},
			}
		}

		props := map[string]any{
			"severity":     string(f.Severity),
			"family":       string(f.Family),
			"status":       string(f.Status),
			"is_quick_win": f.IsQuickWin,
		}
		if len(f.Evidence) > 0 {
			props["evidence"] = f.Evidence
		}
		if len(f.Remediation) > 0 {
			props["remediation"] = f.Remediation
		}

		run.Results = append(run.Results, SARIFResult{
			RuleID:     f.ID,
			Level:      level,
			Message:    SARIFText{Text: messageFor(f)},
			Properties: props,
			Locations: []SARIFLoc{{
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: targetURI},
				},
			}},
		})
	}

	for _, r := range rules {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, r)
	}

	if !r.Scan.StartedAt.IsZero() {
		run.Invocations = []SARIFInvoc{{
			ExecutionSuccessful: true,
			StartTimeUTC:        r.Scan.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			EndTimeUTC:          r.Scan.CompletedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		}}
	}

	doc.Runs = []SARIFRun{run}
	return doc
}

// levelFromSeverity maps our 5-level severity to SARIF's 3-level
// `level` (per spec §6.6: critical/high → error, medium → warning,
// low/info → note).
func levelFromSeverity(s checks.Severity) string {
	switch s {
	case checks.SeverityCritical, checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	case checks.SeverityLow, checks.SeverityInfo:
		return "note"
	}
	return "none"
}

// ruleName transforms `TLS-CERT-EXPIRED` into `TLSCertExpired` for the
// SARIF rule.name slot (camelCase per oasis convention).
func ruleName(id string) string {
	out := make([]rune, 0, len(id))
	capNext := true
	for _, c := range id {
		if c == '-' || c == '_' {
			capNext = true
			continue
		}
		if capNext {
			out = append(out, toUpper(c))
			capNext = false
		} else {
			out = append(out, toLower(c))
		}
	}
	return string(out)
}

func toUpper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}
func toLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

func defaultText(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func messageFor(f FindingEntry) string {
	if f.Description != "" {
		return f.Description
	}
	if f.Title != "" {
		return f.Title
	}
	return f.ID
}
