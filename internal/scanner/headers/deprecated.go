package headers

import (
	"context"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// --- HEADER-XSS-PROTECTION-DEPRECATED --------------------------------

type xssProtectionCheck struct{}

func (xssProtectionCheck) ID() string                       { return IDXSSProtectionDeprec }
func (xssProtectionCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (xssProtectionCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (xssProtectionCheck) Title() string                    { return "X-XSS-Protection is absent or `0`" }
func (xssProtectionCheck) Description() string {
	return "Modern browsers ignore X-XSS-Protection; some legacy filters introduced their own XSS vulnerabilities. Use CSP."
}
func (xssProtectionCheck) RFCRefs() []string { return []string{"OWASP Secure Headers Project"} }

func (xssProtectionCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDXSSProtectionDeprec, checks.SeverityInfo, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDXSSProtectionDeprec, checks.SeverityInfo, "homepage unreachable"), nil
	}
	v := strings.TrimSpace(res.Header("X-XSS-Protection"))
	if v == "" || v == "0" {
		return passFinding(IDXSSProtectionDeprec, checks.SeverityInfo,
			"X-XSS-Protection absent or disabled",
			map[string]any{"value": v}), nil
	}
	return warnFinding(IDXSSProtectionDeprec, checks.SeverityInfo,
		"deprecated X-XSS-Protection enabled",
		"Set `X-XSS-Protection: 0` (or remove it) and rely on CSP.",
		map[string]any{"value": v}), nil
}

// --- HEADER-HPKP-DEPRECATED ------------------------------------------

type hpkpCheck struct{}

func (hpkpCheck) ID() string                       { return IDHPKPDeprecated }
func (hpkpCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (hpkpCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (hpkpCheck) Title() string                    { return "Public-Key-Pins is not set" }
func (hpkpCheck) Description() string {
	return "HPKP is deprecated and dangerous — a misconfigured pin can brick the domain for the pin lifetime."
}
func (hpkpCheck) RFCRefs() []string { return []string{"RFC 7469 (deprecated)"} }

func (hpkpCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDHPKPDeprecated, checks.SeverityMedium, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDHPKPDeprecated, checks.SeverityMedium, "homepage unreachable"), nil
	}
	if v := strings.TrimSpace(res.Header("Public-Key-Pins")); v != "" {
		return failFinding(IDHPKPDeprecated, checks.SeverityMedium,
			"deprecated Public-Key-Pins header set",
			"Remove Public-Key-Pins; rely on Certificate Transparency instead.",
			map[string]any{"value": v}), nil
	}
	if v := strings.TrimSpace(res.Header("Public-Key-Pins-Report-Only")); v != "" {
		return warnFinding(IDHPKPDeprecated, checks.SeverityMedium,
			"deprecated Public-Key-Pins-Report-Only set",
			"Drop the legacy report-only HPKP header.",
			map[string]any{"value": v}), nil
	}
	return passFinding(IDHPKPDeprecated, checks.SeverityMedium,
		"no HPKP header",
		map[string]any{
			"public_key_pins":             "",
			"public_key_pins_report_only": "",
		}), nil
}

// --- HEADER-EXPECT-CT-DEPRECATED -------------------------------------

type expectCTCheck struct{}

func (expectCTCheck) ID() string                       { return IDExpectCTDeprecated }
func (expectCTCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (expectCTCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (expectCTCheck) Title() string                    { return "Expect-CT is not set" }
func (expectCTCheck) Description() string {
	return "Expect-CT is deprecated — Chrome ignored it as of 107; rely on log policy instead."
}
func (expectCTCheck) RFCRefs() []string { return []string{"RFC 9163 (deprecated)"} }

func (expectCTCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDExpectCTDeprecated, checks.SeverityInfo, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDExpectCTDeprecated, checks.SeverityInfo, "homepage unreachable"), nil
	}
	if v := strings.TrimSpace(res.Header("Expect-CT")); v != "" {
		return warnFinding(IDExpectCTDeprecated, checks.SeverityInfo,
			"deprecated Expect-CT header set",
			"Remove Expect-CT; CT enforcement is automatic in modern browsers.",
			map[string]any{"value": v}), nil
	}
	return passFinding(IDExpectCTDeprecated, checks.SeverityInfo,
		"no Expect-CT header",
		map[string]any{"value": ""}), nil
}
