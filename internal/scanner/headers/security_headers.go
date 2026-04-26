package headers

import (
	"context"
	"strings"

	"github.com/Jomar/websec101/internal/checks"
)

// --- HEADER-XCTO-MISSING ---------------------------------------------

type xctoCheck struct{}

func (xctoCheck) ID() string                       { return IDXCTOMissing }
func (xctoCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (xctoCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (xctoCheck) Title() string                    { return "X-Content-Type-Options: nosniff is set" }
func (xctoCheck) Description() string {
	return "Stops MIME-sniffing-based content-type confusion (e.g. text-as-script attacks)."
}
func (xctoCheck) RFCRefs() []string { return []string{"WHATWG Fetch §6.4.7"} }

func (xctoCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDXCTOMissing, checks.SeverityMedium, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDXCTOMissing, checks.SeverityMedium, "homepage unreachable"), nil
	}
	v := strings.ToLower(strings.TrimSpace(res.Header("X-Content-Type-Options")))
	if v != "nosniff" {
		return failFinding(IDXCTOMissing, checks.SeverityMedium,
			"X-Content-Type-Options not set to nosniff",
			"Add `X-Content-Type-Options: nosniff`.", nil), nil
	}
	return passFinding(IDXCTOMissing, checks.SeverityMedium,
		"X-Content-Type-Options: nosniff", nil), nil
}

// --- HEADER-XFO-MISSING ----------------------------------------------

type xfoCheck struct{}

func (xfoCheck) ID() string                       { return IDXFOMissing }
func (xfoCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (xfoCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (xfoCheck) Title() string                    { return "X-Frame-Options is set" }
func (xfoCheck) Description() string {
	return "Legacy clickjacking protection — superseded by CSP frame-ancestors but still required for older browsers."
}
func (xfoCheck) RFCRefs() []string { return []string{"RFC 7034"} }

func (xfoCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDXFOMissing, checks.SeverityMedium, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDXFOMissing, checks.SeverityMedium, "homepage unreachable"), nil
	}
	// CSP frame-ancestors supersedes X-Frame-Options when present.
	if csp := ParseCSP(res.Header("Content-Security-Policy")); csp != nil {
		if _, ok := csp.Directives["frame-ancestors"]; ok {
			return passFinding(IDXFOMissing, checks.SeverityMedium,
				"CSP frame-ancestors supersedes X-Frame-Options", nil), nil
		}
	}
	v := strings.ToLower(strings.TrimSpace(res.Header("X-Frame-Options")))
	switch v {
	case "deny", "sameorigin":
		return passFinding(IDXFOMissing, checks.SeverityMedium,
			"X-Frame-Options: "+v, nil), nil
	case "":
		return failFinding(IDXFOMissing, checks.SeverityMedium,
			"X-Frame-Options not set",
			"Add `X-Frame-Options: DENY` or `SAMEORIGIN`.", nil), nil
	default:
		return failFinding(IDXFOMissing, checks.SeverityMedium,
			"X-Frame-Options has an invalid value",
			"`ALLOW-FROM` is obsolete; use DENY/SAMEORIGIN.",
			map[string]any{"value": v}), nil
	}
}

// --- HEADER-REFERRER-POLICY-MISSING & UNSAFE -------------------------

var safeReferrerPolicies = map[string]bool{
	"no-referrer":                     true,
	"no-referrer-when-downgrade":      true,
	"origin":                          true,
	"origin-when-cross-origin":        true,
	"same-origin":                     true,
	"strict-origin":                   true,
	"strict-origin-when-cross-origin": true,
}

type referrerPolicyMissingCheck struct{}

func (referrerPolicyMissingCheck) ID() string                       { return IDReferrerPolicyMissing }
func (referrerPolicyMissingCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (referrerPolicyMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (referrerPolicyMissingCheck) Title() string                    { return "Referrer-Policy is set" }
func (referrerPolicyMissingCheck) Description() string {
	return "Without an explicit policy, browsers fall back to defaults that vary across vendors."
}
func (referrerPolicyMissingCheck) RFCRefs() []string { return []string{"W3C Referrer Policy"} }

func (referrerPolicyMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDReferrerPolicyMissing, checks.SeverityLow, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDReferrerPolicyMissing, checks.SeverityLow, "homepage unreachable"), nil
	}
	if v := strings.TrimSpace(res.Header("Referrer-Policy")); v == "" {
		return failFinding(IDReferrerPolicyMissing, checks.SeverityLow,
			"Referrer-Policy not set",
			"Add `Referrer-Policy: strict-origin-when-cross-origin` (modern default).", nil), nil
	}
	return passFinding(IDReferrerPolicyMissing, checks.SeverityLow,
		"Referrer-Policy is set",
		map[string]any{"value": res.Header("Referrer-Policy")}), nil
}

type referrerPolicyUnsafeCheck struct{}

func (referrerPolicyUnsafeCheck) ID() string                       { return IDReferrerPolicyUnsafe }
func (referrerPolicyUnsafeCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (referrerPolicyUnsafeCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (referrerPolicyUnsafeCheck) Title() string                    { return "Referrer-Policy avoids `unsafe-url`" }
func (referrerPolicyUnsafeCheck) Description() string {
	return "`unsafe-url` leaks the full URL (including query) to every cross-origin request."
}
func (referrerPolicyUnsafeCheck) RFCRefs() []string { return []string{"W3C Referrer Policy"} }

func (referrerPolicyUnsafeCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDReferrerPolicyUnsafe, checks.SeverityMedium, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDReferrerPolicyUnsafe, checks.SeverityMedium, "homepage unreachable"), nil
	}
	v := strings.ToLower(strings.TrimSpace(res.Header("Referrer-Policy")))
	if v == "" {
		return skippedFinding(IDReferrerPolicyUnsafe, checks.SeverityMedium, "no Referrer-Policy"), nil
	}
	for _, tok := range strings.Split(v, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "unsafe-url" {
			return failFinding(IDReferrerPolicyUnsafe, checks.SeverityMedium,
				"Referrer-Policy includes `unsafe-url`", "", map[string]any{"value": v}), nil
		}
		if !safeReferrerPolicies[tok] {
			return warnFinding(IDReferrerPolicyUnsafe, checks.SeverityMedium,
				"Referrer-Policy includes a non-standard token",
				"Token "+tok+" is not in the W3C list.", map[string]any{"value": v}), nil
		}
	}
	return passFinding(IDReferrerPolicyUnsafe, checks.SeverityMedium,
		"Referrer-Policy is conservative",
		map[string]any{"value": v}), nil
}

// --- HEADER-PERMISSIONS-POLICY-MISSING -------------------------------

type permissionsPolicyMissingCheck struct{}

func (permissionsPolicyMissingCheck) ID() string                       { return IDPermissionsPolicyMiss }
func (permissionsPolicyMissingCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (permissionsPolicyMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (permissionsPolicyMissingCheck) Title() string                    { return "Permissions-Policy is set" }
func (permissionsPolicyMissingCheck) Description() string {
	return "Permissions-Policy gates powerful APIs (camera, microphone, geolocation, ...)."
}
func (permissionsPolicyMissingCheck) RFCRefs() []string { return []string{"W3C Permissions Policy"} }

func (permissionsPolicyMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDPermissionsPolicyMiss, checks.SeverityLow, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDPermissionsPolicyMiss, checks.SeverityLow, "homepage unreachable"), nil
	}
	if strings.TrimSpace(res.Header("Permissions-Policy")) == "" {
		return failFinding(IDPermissionsPolicyMiss, checks.SeverityLow,
			"Permissions-Policy not set",
			"Even an empty allowlist (`camera=()`) is better than nothing.", nil), nil
	}
	return passFinding(IDPermissionsPolicyMiss, checks.SeverityLow,
		"Permissions-Policy is set",
		map[string]any{"value": res.Header("Permissions-Policy")}), nil
}

// --- HEADER-FEATURE-POLICY-DEPRECATED --------------------------------

type featurePolicyDeprecatedCheck struct{}

func (featurePolicyDeprecatedCheck) ID() string                       { return IDFeaturePolicyDeprec }
func (featurePolicyDeprecatedCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (featurePolicyDeprecatedCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (featurePolicyDeprecatedCheck) Title() string                    { return "Feature-Policy header is not used" }
func (featurePolicyDeprecatedCheck) Description() string {
	return "Feature-Policy is deprecated in favour of Permissions-Policy."
}
func (featurePolicyDeprecatedCheck) RFCRefs() []string { return []string{"W3C Permissions Policy"} }

func (featurePolicyDeprecatedCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDFeaturePolicyDeprec, checks.SeverityInfo, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDFeaturePolicyDeprec, checks.SeverityInfo, "homepage unreachable"), nil
	}
	if strings.TrimSpace(res.Header("Feature-Policy")) != "" {
		return warnFinding(IDFeaturePolicyDeprec, checks.SeverityInfo,
			"deprecated Feature-Policy header is set",
			"Migrate to Permissions-Policy.", nil), nil
	}
	return passFinding(IDFeaturePolicyDeprec, checks.SeverityInfo,
		"no deprecated Feature-Policy", nil), nil
}

// --- HEADER-COOP/COEP/CORP --------------------------------------------

type coopCheck struct{}

func (coopCheck) ID() string                       { return IDCOOPMissing }
func (coopCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (coopCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (coopCheck) Title() string                    { return "Cross-Origin-Opener-Policy is set" }
func (coopCheck) Description() string {
	return "COOP isolates the browsing context group, blocking Spectre-style cross-origin reads."
}
func (coopCheck) RFCRefs() []string { return []string{"WHATWG HTML"} }

func (coopCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return simplePresenceCheck(ctx, t, IDCOOPMissing, checks.SeverityLow,
		"Cross-Origin-Opener-Policy",
		"Add `Cross-Origin-Opener-Policy: same-origin` (or `same-origin-allow-popups`).")
}

type coepCheck struct{}

func (coepCheck) ID() string                       { return IDCOEPMissing }
func (coepCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (coepCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (coepCheck) Title() string                    { return "Cross-Origin-Embedder-Policy is set" }
func (coepCheck) Description() string {
	return "COEP unlocks SharedArrayBuffer and high-resolution timers in cross-origin-isolated contexts."
}
func (coepCheck) RFCRefs() []string { return []string{"WHATWG HTML"} }

func (coepCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return simplePresenceCheck(ctx, t, IDCOEPMissing, checks.SeverityLow,
		"Cross-Origin-Embedder-Policy",
		"Add `Cross-Origin-Embedder-Policy: require-corp` (after auditing your sub-resources).")
}

type corpCheck struct{}

func (corpCheck) ID() string                       { return IDCORPMissing }
func (corpCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (corpCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (corpCheck) Title() string                    { return "Cross-Origin-Resource-Policy is set" }
func (corpCheck) Description() string {
	return "CORP lets you opt static resources out of cross-origin reads."
}
func (corpCheck) RFCRefs() []string { return []string{"WHATWG Fetch"} }

func (corpCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return simplePresenceCheck(ctx, t, IDCORPMissing, checks.SeverityLow,
		"Cross-Origin-Resource-Policy",
		"Add `Cross-Origin-Resource-Policy: same-origin` (or `same-site`).")
}

// --- HEADER-REPORTING-ENDPOINTS / NEL ----------------------------------

type reportingEndpointsCheck struct{}

func (reportingEndpointsCheck) ID() string                       { return IDReportingEndpointsNo }
func (reportingEndpointsCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (reportingEndpointsCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (reportingEndpointsCheck) Title() string                    { return "Reporting endpoints are configured" }
func (reportingEndpointsCheck) Description() string {
	return "Reporting-Endpoints (or legacy Report-To) lets browsers send violation reports to a collector."
}
func (reportingEndpointsCheck) RFCRefs() []string { return []string{"W3C Reporting API"} }

func (reportingEndpointsCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDReportingEndpointsNo, checks.SeverityInfo, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDReportingEndpointsNo, checks.SeverityInfo, "homepage unreachable"), nil
	}
	if v := res.Header("Reporting-Endpoints"); v != "" {
		return passFinding(IDReportingEndpointsNo, checks.SeverityInfo,
			"Reporting-Endpoints is set",
			map[string]any{"value": v}), nil
	}
	if v := res.Header("Report-To"); v != "" {
		return warnFinding(IDReportingEndpointsNo, checks.SeverityInfo,
			"only legacy Report-To is set",
			"Migrate to Reporting-Endpoints (Report-To is deprecated).",
			map[string]any{"value": v}), nil
	}
	return failFinding(IDReportingEndpointsNo, checks.SeverityInfo,
		"no reporting endpoint configured", "", nil), nil
}

type nelCheck struct{}

func (nelCheck) ID() string                       { return IDNELNone }
func (nelCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (nelCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (nelCheck) Title() string                    { return "NEL (Network Error Logging) is set" }
func (nelCheck) Description() string {
	return "NEL streams transport-level errors back to a collector — useful but optional."
}
func (nelCheck) RFCRefs() []string { return []string{"W3C NEL"} }

func (nelCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return simplePresenceCheck(ctx, t, IDNELNone, checks.SeverityInfo,
		"NEL",
		"Optional: enable NEL alongside Reporting-Endpoints if you want client-side telemetry.")
}

// simplePresenceCheck is the shared logic for "header X must exist".
func simplePresenceCheck(ctx context.Context, t *checks.Target, id string, sev checks.Severity, headerName, suggestion string) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(id, sev, err), nil
	}
	if !res.Reachable {
		return skippedFinding(id, sev, "homepage unreachable"), nil
	}
	if strings.TrimSpace(res.Header(headerName)) == "" {
		return failFinding(id, sev,
			headerName+" not set", suggestion, nil), nil
	}
	return passFinding(id, sev,
		headerName+" is set",
		map[string]any{"value": res.Header(headerName)}), nil
}
