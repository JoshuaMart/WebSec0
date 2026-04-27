package email

import (
	"context"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// DMARC is the parsed shape of a `v=DMARC1 …` record.
type DMARC struct {
	Raw    string
	Tags   map[string]string
	Errors []string
}

// ParseDMARC parses a DMARC record. Returns nil for empty input.
func ParseDMARC(raw string) *DMARC {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	d := &DMARC{Raw: raw, Tags: map[string]string{}}
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return d
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			d.Errors = append(d.Errors, "term without '=': "+p)
			continue
		}
		d.Tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if v, ok := d.Tags["v"]; !ok || !strings.EqualFold(v, "DMARC1") {
		d.Errors = append(d.Errors, "missing or invalid v= tag")
	}
	if _, ok := d.Tags["p"]; !ok {
		d.Errors = append(d.Errors, "missing required p= tag")
	}
	return d
}

// --- EMAIL-DMARC-MISSING ---------------------------------------------

type dmarcMissingCheck struct{}

func (dmarcMissingCheck) ID() string                       { return IDDMARCMissing }
func (dmarcMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (dmarcMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (dmarcMissingCheck) Title() string                    { return "Domain publishes DMARC" }
func (dmarcMissingCheck) Description() string {
	return "DMARC (RFC 7489) instructs receivers what to do when SPF and DKIM both fail."
}
func (dmarcMissingCheck) RFCRefs() []string { return []string{"RFC 7489"} }

func (dmarcMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDMARCMissing, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDDMARCMissing, checks.SeverityHigh); g != nil {
		return g, nil
	}
	if r.DMARC == "" {
		f := fail(IDDMARCMissing, checks.SeverityHigh,
			"no DMARC record",
			"Publish a TXT record `v=DMARC1; p=reject; rua=mailto:…` on `_dmarc.<domain>`.", nil)
		f.Remediation = map[string]any{
			"why_it_matters": "DMARC tells receiving mail servers how to handle messages that fail SPF or DKIM checks. Without it, anyone can send email appearing to come from your domain, enabling phishing attacks against your users and partners.",
			"impact":         "Enables impersonation of your brand in phishing campaigns. Also required by Google and Yahoo for bulk senders. No DMARC means no reporting visibility into who is sending on your behalf.",
			"references": []map[string]any{
				{"title": "RFC 7489 — DMARC", "url": "https://www.rfc-editor.org/rfc/rfc7489"},
				{"title": "dmarc.org — Overview and tools", "url": "https://dmarc.org/"},
			},
			"snippets": map[string]any{
				"dns": "# TXT record on _dmarc.example.com\nv=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s",
			},
			"verification": "dig TXT _dmarc.example.com +short",
		}
		return f, nil
	}
	return pass(IDDMARCMissing, checks.SeverityHigh,
		"DMARC record present",
		map[string]any{"raw": r.DMARC}), nil
}

// --- EMAIL-DMARC-INVALID-SYNTAX --------------------------------------

type dmarcInvalidSyntaxCheck struct{}

func (dmarcInvalidSyntaxCheck) ID() string                       { return IDDMARCInvalidSyntax }
func (dmarcInvalidSyntaxCheck) Family() checks.Family            { return checks.FamilyEmail }
func (dmarcInvalidSyntaxCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (dmarcInvalidSyntaxCheck) Title() string                    { return "DMARC record is syntactically valid" }
func (dmarcInvalidSyntaxCheck) Description() string {
	return "Malformed DMARC records are silently ignored by receivers."
}
func (dmarcInvalidSyntaxCheck) RFCRefs() []string { return []string{"RFC 7489"} }

func (dmarcInvalidSyntaxCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDMARCInvalidSyntax, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDDMARCInvalidSyntax, checks.SeverityHigh); g != nil {
		return g, nil
	}
	if r.DMARC == "" {
		return skipped(IDDMARCInvalidSyntax, checks.SeverityHigh, "no DMARC record"), nil
	}
	parsed := ParseDMARC(r.DMARC)
	if parsed != nil && len(parsed.Errors) > 0 {
		return fail(IDDMARCInvalidSyntax, checks.SeverityHigh,
			"DMARC parse errors",
			strings.Join(parsed.Errors, "; "),
			map[string]any{"errors": parsed.Errors}), nil
	}
	return pass(IDDMARCInvalidSyntax, checks.SeverityHigh,
		"DMARC parses cleanly", nil), nil
}

// --- EMAIL-DMARC-POLICY-NONE -----------------------------------------

type dmarcPolicyNoneCheck struct{}

func (dmarcPolicyNoneCheck) ID() string                       { return IDDMARCPolicyNone }
func (dmarcPolicyNoneCheck) Family() checks.Family            { return checks.FamilyEmail }
func (dmarcPolicyNoneCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (dmarcPolicyNoneCheck) Title() string                    { return "DMARC policy is enforcing (not `p=none`)" }
func (dmarcPolicyNoneCheck) Description() string {
	return "`p=none` is monitor-only — receivers will still deliver forgeries."
}
func (dmarcPolicyNoneCheck) RFCRefs() []string { return []string{"RFC 7489"} }

func (dmarcPolicyNoneCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDMARCPolicyNone, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDDMARCPolicyNone, checks.SeverityMedium); g != nil {
		return g, nil
	}
	if r.DMARC == "" {
		return skipped(IDDMARCPolicyNone, checks.SeverityMedium, "no DMARC record"), nil
	}
	parsed := ParseDMARC(r.DMARC)
	if parsed == nil {
		return skipped(IDDMARCPolicyNone, checks.SeverityMedium, "parse failed"), nil
	}
	p := strings.ToLower(parsed.Tags["p"])
	if p == "none" {
		return fail(IDDMARCPolicyNone, checks.SeverityMedium,
			"DMARC policy is `none` (monitor-only)",
			"Move to `p=quarantine` and then `p=reject` once monitoring is clean.",
			map[string]any{"policy": p}), nil
	}
	return pass(IDDMARCPolicyNone, checks.SeverityMedium,
		"DMARC policy is enforcing",
		map[string]any{"policy": p}), nil
}

// --- EMAIL-DMARC-POLICY-WEAK -----------------------------------------

type dmarcPolicyWeakCheck struct{}

func (dmarcPolicyWeakCheck) ID() string                       { return IDDMARCPolicyWeak }
func (dmarcPolicyWeakCheck) Family() checks.Family            { return checks.FamilyEmail }
func (dmarcPolicyWeakCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (dmarcPolicyWeakCheck) Title() string                    { return "DMARC policy is `p=reject`" }
func (dmarcPolicyWeakCheck) Description() string {
	return "`quarantine` reduces forgery delivery; `reject` is stricter and recommended once stable."
}
func (dmarcPolicyWeakCheck) RFCRefs() []string { return []string{"RFC 7489"} }

func (dmarcPolicyWeakCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDMARCPolicyWeak, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDDMARCPolicyWeak, checks.SeverityLow); g != nil {
		return g, nil
	}
	if r.DMARC == "" {
		return skipped(IDDMARCPolicyWeak, checks.SeverityLow, "no DMARC record"), nil
	}
	parsed := ParseDMARC(r.DMARC)
	if parsed == nil {
		return skipped(IDDMARCPolicyWeak, checks.SeverityLow, "parse failed"), nil
	}
	p := strings.ToLower(parsed.Tags["p"])
	pct := parsed.Tags["pct"]
	switch p {
	case "reject":
		if pct == "" || pct == "100" {
			return pass(IDDMARCPolicyWeak, checks.SeverityLow,
				"DMARC reject 100%", nil), nil
		}
		return warn(IDDMARCPolicyWeak, checks.SeverityLow,
			"DMARC reject with pct < 100",
			"Ramp pct up to 100 once monitoring confirms no false positives.",
			map[string]any{"pct": pct}), nil
	case "quarantine":
		return warn(IDDMARCPolicyWeak, checks.SeverityLow,
			"DMARC at quarantine",
			"Tighten to `p=reject` when ready.", nil), nil
	default:
		return skipped(IDDMARCPolicyWeak, checks.SeverityLow, "policy is none"), nil
	}
}

// --- EMAIL-DMARC-NO-RUA ----------------------------------------------

type dmarcNoRUACheck struct{}

func (dmarcNoRUACheck) ID() string                       { return IDDMARCNoRUA }
func (dmarcNoRUACheck) Family() checks.Family            { return checks.FamilyEmail }
func (dmarcNoRUACheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (dmarcNoRUACheck) Title() string                    { return "DMARC defines an aggregate-report endpoint (rua=)" }
func (dmarcNoRUACheck) Description() string {
	return "Without `rua=mailto:…`, you have no visibility into spoofing attempts."
}
func (dmarcNoRUACheck) RFCRefs() []string { return []string{"RFC 7489"} }

func (dmarcNoRUACheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDMARCNoRUA, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDDMARCNoRUA, checks.SeverityLow); g != nil {
		return g, nil
	}
	if r.DMARC == "" {
		return skipped(IDDMARCNoRUA, checks.SeverityLow, "no DMARC record"), nil
	}
	parsed := ParseDMARC(r.DMARC)
	if parsed == nil {
		return skipped(IDDMARCNoRUA, checks.SeverityLow, "parse failed"), nil
	}
	if strings.TrimSpace(parsed.Tags["rua"]) == "" {
		return fail(IDDMARCNoRUA, checks.SeverityLow,
			"no `rua=` tag",
			"Add `rua=mailto:dmarc-aggregate@<domain>` to receive daily reports.", nil), nil
	}
	return pass(IDDMARCNoRUA, checks.SeverityLow,
		"`rua=` tag present",
		map[string]any{"rua": parsed.Tags["rua"]}), nil
}
