package tls

import (
	"context"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// --- TLS-REDIRECT-HTTP-TO-HTTPS ---------------------------------------

type httpRedirectCheck struct{}

func (httpRedirectCheck) ID() string                       { return IDRedirectHTTPToHTTPS }
func (httpRedirectCheck) Family() checks.Family            { return checks.FamilyTLS }
func (httpRedirectCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (httpRedirectCheck) Title() string                    { return "Plain HTTP redirects to HTTPS" }
func (httpRedirectCheck) Description() string {
	return "A plain http:// hit must respond 301/308 to an https:// URL so legacy clients land on TLS."
}
func (httpRedirectCheck) RFCRefs() []string { return []string{"RFC 7230 §6"} }

func (httpRedirectCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDRedirectHTTPToHTTPS, checks.SeverityHigh, err), nil
	}
	hp := res.HTTPProbe
	if hp == nil || hp.RedirectErr != nil {
		// Plain HTTP unreachable — could be a firewall, an HTTPS-only
		// listener, or a real outage. Don't fail the scan; report skipped.
		reason := "HTTP unreachable"
		if hp != nil && hp.RedirectErr != nil {
			reason = hp.RedirectErr.Error()
		}
		return skippedFinding(IDRedirectHTTPToHTTPS, checks.SeverityHigh, reason), nil
	}
	ev := map[string]any{
		"status":   hp.StatusCode,
		"location": hp.Location,
	}
	switch {
	case hp.StatusCode >= 300 && hp.StatusCode < 400 && hp.IsHTTPS:
		return passFinding(IDRedirectHTTPToHTTPS, checks.SeverityHigh,
			"HTTP→HTTPS redirect in place", ev), nil
	case hp.StatusCode >= 300 && hp.StatusCode < 400:
		return failFinding(IDRedirectHTTPToHTTPS, checks.SeverityHigh,
			"HTTP redirect does not point at HTTPS",
			"The 3xx Location header was not an https:// URL.", ev), nil
	default:
		return failFinding(IDRedirectHTTPToHTTPS, checks.SeverityHigh,
			"plain HTTP serves content directly",
			"No redirect to HTTPS — clients can be downgraded.", ev), nil
	}
}
