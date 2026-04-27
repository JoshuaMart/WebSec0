package tls

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// HSTSPolicy is the parsed shape of a Strict-Transport-Security header.
type HSTSPolicy struct {
	MaxAge            time.Duration
	IncludeSubDomains bool
	Preload           bool
}

// ParseHSTS parses a single Strict-Transport-Security header value. ok=false
// is returned for malformed/empty input.
func ParseHSTS(raw string) (HSTSPolicy, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return HSTSPolicy{}, false
	}
	var p HSTSPolicy
	gotMaxAge := false
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "max-age":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				continue
			}
			p.MaxAge = time.Duration(n) * time.Second
			gotMaxAge = true
		case "includesubdomains":
			p.IncludeSubDomains = true
		case "preload":
			p.Preload = true
		}
	}
	if !gotMaxAge {
		return HSTSPolicy{}, false
	}
	return p, true
}

// Recommended baseline is a year — Chrome's HSTS preload list and most
// browser hardening guides agree.
const hstsMinMaxAge = 365 * 24 * time.Hour

// --- TLS-HSTS-MISSING -------------------------------------------------

type hstsMissingCheck struct{}

func (hstsMissingCheck) ID() string                       { return IDHSTSMissing }
func (hstsMissingCheck) Family() checks.Family            { return checks.FamilyTLS }
func (hstsMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (hstsMissingCheck) Title() string                    { return "HSTS is set" }
func (hstsMissingCheck) Description() string {
	return "Strict-Transport-Security (RFC 6797) protects against SSL-stripping and downgrade attacks."
}
func (hstsMissingCheck) RFCRefs() []string { return []string{"RFC 6797"} }

func (hstsMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDHSTSMissing, checks.SeverityHigh, err), nil
	}
	if !res.AnySucceeded {
		return skippedFinding(IDHSTSMissing, checks.SeverityHigh, "HTTPS unreachable"), nil
	}
	if _, ok := ParseHSTS(res.HSTSHeader); !ok {
		return failFinding(IDHSTSMissing, checks.SeverityHigh,
			"no Strict-Transport-Security header",
			"The HTTPS root response did not include an HSTS header.",
			map[string]any{"raw_header": res.HSTSHeader}), nil
	}
	return passFinding(IDHSTSMissing, checks.SeverityHigh,
		"HSTS header present",
		map[string]any{"raw_header": res.HSTSHeader}), nil
}

// --- TLS-HSTS-MAX-AGE-LOW ---------------------------------------------

type hstsMaxAgeLowCheck struct{}

func (hstsMaxAgeLowCheck) ID() string                       { return IDHSTSMaxAgeLow }
func (hstsMaxAgeLowCheck) Family() checks.Family            { return checks.FamilyTLS }
func (hstsMaxAgeLowCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (hstsMaxAgeLowCheck) Title() string                    { return "HSTS max-age is at least one year" }
func (hstsMaxAgeLowCheck) Description() string {
	return "Browsers expect max-age ≥ 31536000 to honour the policy long-term and to qualify for preload."
}
func (hstsMaxAgeLowCheck) RFCRefs() []string { return []string{"RFC 6797"} }

func (hstsMaxAgeLowCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDHSTSMaxAgeLow, checks.SeverityMedium, err), nil
	}
	if !res.AnySucceeded {
		return skippedFinding(IDHSTSMaxAgeLow, checks.SeverityMedium, "HTTPS unreachable"), nil
	}
	p, ok := ParseHSTS(res.HSTSHeader)
	if !ok {
		return skippedFinding(IDHSTSMaxAgeLow, checks.SeverityMedium, "HSTS header missing"), nil
	}
	ev := map[string]any{"max_age_seconds": int(p.MaxAge.Seconds())}
	if p.MaxAge < hstsMinMaxAge {
		return failFinding(IDHSTSMaxAgeLow, checks.SeverityMedium,
			"HSTS max-age below one year",
			"Recommended: max-age=31536000.", ev), nil
	}
	return passFinding(IDHSTSMaxAgeLow, checks.SeverityMedium,
		"HSTS max-age ≥ 1 year", ev), nil
}

// --- TLS-HSTS-NO-INCLUDESUBDOMAINS ------------------------------------

type hstsNoIncludeSubCheck struct{}

func (hstsNoIncludeSubCheck) ID() string                       { return IDHSTSNoIncludeSubDomains }
func (hstsNoIncludeSubCheck) Family() checks.Family            { return checks.FamilyTLS }
func (hstsNoIncludeSubCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (hstsNoIncludeSubCheck) Title() string                    { return "HSTS covers subdomains" }
func (hstsNoIncludeSubCheck) Description() string {
	return "Add `includeSubDomains` so cookies leaked from a subdomain via plain HTTP are not exploitable."
}
func (hstsNoIncludeSubCheck) RFCRefs() []string { return []string{"RFC 6797"} }

func (hstsNoIncludeSubCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDHSTSNoIncludeSubDomains, checks.SeverityLow, err), nil
	}
	if !res.AnySucceeded {
		return skippedFinding(IDHSTSNoIncludeSubDomains, checks.SeverityLow, "HTTPS unreachable"), nil
	}
	p, ok := ParseHSTS(res.HSTSHeader)
	if !ok {
		return skippedFinding(IDHSTSNoIncludeSubDomains, checks.SeverityLow, "HSTS header missing"), nil
	}
	if !p.IncludeSubDomains {
		return failFinding(IDHSTSNoIncludeSubDomains, checks.SeverityLow,
			"HSTS without includeSubDomains",
			"Subdomains are not protected by this policy.", nil), nil
	}
	return passFinding(IDHSTSNoIncludeSubDomains, checks.SeverityLow,
		"HSTS covers subdomains", nil), nil
}
