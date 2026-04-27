package http

import (
	"context"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// dangerousMethods are HTTP verbs that should not be reachable on a
// public web root unless explicitly intended.
var dangerousMethods = []string{"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}

// --- HTTP-OPTIONS-DANGEROUS-METHODS ----------------------------------

type optionsCheck struct{}

func (optionsCheck) ID() string                       { return IDOptionsDangerousMethods }
func (optionsCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (optionsCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (optionsCheck) Title() string                    { return "OPTIONS does not advertise dangerous methods" }
func (optionsCheck) Description() string {
	return "PUT / DELETE / PATCH / TRACE / CONNECT in `Allow:` suggest the public root accepts mutating verbs."
}
func (optionsCheck) RFCRefs() []string { return []string{"RFC 9110 §9.3.7"} }

func (optionsCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDOptionsDangerousMethods, checks.FamilyHTTP, checks.SeverityMedium, err), nil
	}
	if res.Options == nil || res.Options.Err != nil {
		reason := "OPTIONS unreachable"
		if res.Options != nil && res.Options.Err != nil {
			reason = res.Options.Err.Error()
		}
		return skipped(IDOptionsDangerousMethods, checks.FamilyHTTP, checks.SeverityMedium, reason), nil
	}
	allow := res.Options.Headers.Get("Allow")
	if allow == "" {
		return pass(IDOptionsDangerousMethods, checks.FamilyHTTP, checks.SeverityMedium,
			"no Allow header on OPTIONS", nil), nil
	}
	upper := strings.ToUpper(allow)
	var found []string
	for _, m := range dangerousMethods {
		if strings.Contains(upper, m) {
			found = append(found, m)
		}
	}
	if len(found) > 0 {
		return fail(IDOptionsDangerousMethods, checks.FamilyHTTP, checks.SeverityMedium,
			"OPTIONS advertises dangerous methods",
			"Restrict the public root to GET / HEAD / OPTIONS.",
			map[string]any{"allow": allow, "dangerous": found}), nil
	}
	return pass(IDOptionsDangerousMethods, checks.FamilyHTTP, checks.SeverityMedium,
		"OPTIONS Allow looks safe",
		map[string]any{"allow": allow}), nil
}

// --- HTTP-TRACE-ENABLED ----------------------------------------------

type traceCheck struct{}

func (traceCheck) ID() string                       { return IDTraceEnabled }
func (traceCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (traceCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (traceCheck) Title() string                    { return "TRACE is disabled" }
func (traceCheck) Description() string {
	return "TRACE echoes the request and historically enables Cross-Site Tracing (XST) attacks; disable at the proxy."
}
func (traceCheck) RFCRefs() []string { return []string{"RFC 9110 §9.3.8"} }

func (traceCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDTraceEnabled, checks.FamilyHTTP, checks.SeverityMedium, err), nil
	}
	if res.Trace == nil || res.Trace.Err != nil {
		reason := "TRACE unreachable"
		if res.Trace != nil && res.Trace.Err != nil {
			reason = res.Trace.Err.Error()
		}
		return skipped(IDTraceEnabled, checks.FamilyHTTP, checks.SeverityMedium, reason), nil
	}
	if res.Trace.Status >= 200 && res.Trace.Status < 300 {
		return fail(IDTraceEnabled, checks.FamilyHTTP, checks.SeverityMedium,
			"TRACE returns 2xx",
			"Disable TRACE in your reverse-proxy / framework.",
			map[string]any{"status": res.Trace.Status}), nil
	}
	return pass(IDTraceEnabled, checks.FamilyHTTP, checks.SeverityMedium,
		"TRACE refused",
		map[string]any{"status": res.Trace.Status}), nil
}
