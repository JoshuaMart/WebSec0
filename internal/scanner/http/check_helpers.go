package http

import "github.com/JoshuaMart/websec0/internal/checks"

// Check IDs.
const (
	IDHTTP2Missing            = "HTTP-HTTP2-MISSING"
	IDHTTP3Missing            = "HTTP-HTTP3-MISSING"
	IDMixedContent            = "HTTP-MIXED-CONTENT"
	IDOptionsDangerousMethods = "HTTP-OPTIONS-DANGEROUS-METHODS"
	IDTraceEnabled            = "HTTP-TRACE-ENABLED"
	IDCORSWildcardCredentials = "HTTP-CORS-WILDCARD-CREDENTIALS" //#nosec G101 -- public check identifier, not a credential
	IDCORSOriginReflected     = "HTTP-CORS-ORIGIN-REFLECTED"
	IDCORSNullOrigin          = "HTTP-CORS-NULL-ORIGIN"
	ID404StackTrace           = "HTTP-404-STACK-TRACE"
	ID404DefaultErrorPage     = "HTTP-404-DEFAULT-ERROR-PAGE"
	IDCompressionNone         = "HTTP-COMPRESSION-NONE"
	IDRobotsTxtInvalid        = "ROBOTS-TXT-INVALID"
	IDChangePasswordMissing   = "WELLKNOWN-CHANGE-PASSWORD-MISSING"
	IDSRIExternalNoIntegrity  = "SRI-EXTERNAL-RESOURCE-NO-INTEGRITY"
)

func errFinding(id string, fam checks.Family, sev checks.Severity, err error) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: fam, Severity: sev,
		Status: checks.StatusError, Title: "http: probe error", Description: err.Error(),
	}
}
func skipped(id string, fam checks.Family, sev checks.Severity, reason string) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: fam, Severity: sev,
		Status: checks.StatusSkipped, Title: "skipped: " + reason,
	}
}
func pass(id string, fam checks.Family, sev checks.Severity, title string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: fam, Severity: sev,
		Status: checks.StatusPass, Title: title, Evidence: ev,
	}
}
func fail(id string, fam checks.Family, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: fam, Severity: sev,
		Status: checks.StatusFail, Title: title, Description: desc, Evidence: ev,
	}
}
func warn(id string, fam checks.Family, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: fam, Severity: sev,
		Status: checks.StatusWarn, Title: title, Description: desc, Evidence: ev,
	}
}
