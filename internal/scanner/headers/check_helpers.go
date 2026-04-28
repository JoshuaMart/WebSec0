package headers

import "github.com/JoshuaMart/websec0/internal/checks"

// Check IDs for the HTTP-headers family.
const (
	IDCSPMissing            = "HEADER-CSP-MISSING"
	IDCSPUnsafeInline       = "HEADER-CSP-UNSAFE-INLINE"
	IDCSPUnsafeEval         = "HEADER-CSP-UNSAFE-EVAL"
	IDCSPWildcardSrc        = "HEADER-CSP-WILDCARD-SRC" //#nosec G101 -- public check identifier, not a credential
	IDCSPNoObjectSrc        = "HEADER-CSP-NO-OBJECT-SRC"
	IDCSPNoBaseURI          = "HEADER-CSP-NO-BASE-URI"
	IDCSPNoFrameAncestors   = "HEADER-CSP-NO-FRAME-ANCESTORS"
	IDXCTOMissing           = "HEADER-XCTO-MISSING"
	IDXFOMissing            = "HEADER-XFO-MISSING"
	IDReferrerPolicyMissing = "HEADER-REFERRER-POLICY-MISSING"
	IDReferrerPolicyUnsafe  = "HEADER-REFERRER-POLICY-UNSAFE"
	IDPermissionsPolicyMiss = "HEADER-PERMISSIONS-POLICY-MISSING"
	IDFeaturePolicyDeprec   = "HEADER-FEATURE-POLICY-DEPRECATED"
	IDCOOPMissing           = "HEADER-COOP-MISSING"
	IDCOEPMissing           = "HEADER-COEP-MISSING"
	IDCORPMissing           = "HEADER-CORP-MISSING"
	IDReportingEndpointsNo  = "HEADER-REPORTING-ENDPOINTS-NONE"
	IDNELNone               = "HEADER-NEL-NONE"
	IDXSSProtectionDeprec   = "HEADER-XSS-PROTECTION-DEPRECATED"
	IDHPKPDeprecated        = "HEADER-HPKP-DEPRECATED"
	IDExpectCTDeprecated    = "HEADER-EXPECT-CT-DEPRECATED"
	IDInfoServer            = "HEADER-INFO-SERVER"
	IDInfoXPoweredBy        = "HEADER-INFO-X-POWERED-BY"
	IDInfoXAspNetVersion    = "HEADER-INFO-X-ASPNET-VERSION"
	IDInfoXGenerator        = "HEADER-INFO-X-GENERATOR"
	IDInfoServerTiming      = "HEADER-INFO-SERVER-TIMING"
)

func errFinding(id string, sev checks.Severity, err error) *checks.Finding {
	return &checks.Finding{
		ID:          id,
		Family:      checks.FamilyHeaders,
		Severity:    sev,
		Status:      checks.StatusError,
		Title:       "headers: probe error",
		Description: err.Error(),
	}
}

func skippedFinding(id string, sev checks.Severity, reason string) *checks.Finding {
	return &checks.Finding{
		ID:       id,
		Family:   checks.FamilyHeaders,
		Severity: sev,
		Status:   checks.StatusSkipped,
		Title:    "skipped: " + reason,
	}
}

func passFinding(id string, sev checks.Severity, title string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID:       id,
		Family:   checks.FamilyHeaders,
		Severity: sev,
		Status:   checks.StatusPass,
		Title:    title,
		Evidence: ev,
	}
}

func failFinding(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID:          id,
		Family:      checks.FamilyHeaders,
		Severity:    sev,
		Status:      checks.StatusFail,
		Title:       title,
		Description: desc,
		Evidence:    ev,
	}
}

func warnFinding(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID:          id,
		Family:      checks.FamilyHeaders,
		Severity:    sev,
		Status:      checks.StatusWarn,
		Title:       title,
		Description: desc,
		Evidence:    ev,
	}
}
