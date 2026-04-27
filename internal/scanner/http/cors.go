package http

import (
	"context"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/headers"
)

// --- HTTP-CORS-WILDCARD-CREDENTIALS ----------------------------------
//
// Detected on the homepage response itself: ACAO=`*` together with
// ACAC=`true` is rejected by browsers, but flagging it on the server
// side surfaces misconfigured edges before users notice.

type corsWildcardCredCheck struct{}

func (corsWildcardCredCheck) ID() string                       { return IDCORSWildcardCredentials }
func (corsWildcardCredCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (corsWildcardCredCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (corsWildcardCredCheck) Title() string {
	return "CORS does not combine wildcard origin with credentials"
}
func (corsWildcardCredCheck) Description() string {
	return "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is forbidden by the spec; servers shouldn't ship this combination."
}
func (corsWildcardCredCheck) RFCRefs() []string { return []string{"WHATWG Fetch §3.2"} }

func (corsWildcardCredCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := headers.Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCORSWildcardCredentials, checks.FamilyHTTP, checks.SeverityHigh, err), nil
	}
	if !res.Reachable {
		return skipped(IDCORSWildcardCredentials, checks.FamilyHTTP, checks.SeverityHigh, "homepage unreachable"), nil
	}
	acao := strings.TrimSpace(res.Header("Access-Control-Allow-Origin"))
	acac := strings.ToLower(strings.TrimSpace(res.Header("Access-Control-Allow-Credentials")))
	if acao == "*" && acac == "true" {
		return fail(IDCORSWildcardCredentials, checks.FamilyHTTP, checks.SeverityHigh,
			"CORS wildcard with credentials",
			"Switch to a strict allowlist or drop credentials.", nil), nil
	}
	return pass(IDCORSWildcardCredentials, checks.FamilyHTTP, checks.SeverityHigh,
		"no wildcard+credentials combination",
		map[string]any{"acao": acao, "acac": acac}), nil
}

// --- HTTP-CORS-ORIGIN-REFLECTED --------------------------------------
//
// We GET / with `Origin: https://websec0-test.invalid`. If the
// server reflects that origin verbatim AND attaches credentials, any
// cross-origin attacker can read authenticated responses.

type corsReflectedCheck struct{}

func (corsReflectedCheck) ID() string                       { return IDCORSOriginReflected }
func (corsReflectedCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (corsReflectedCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (corsReflectedCheck) Title() string                    { return "CORS does not reflect arbitrary origins" }
func (corsReflectedCheck) Description() string {
	return "Reflecting the request Origin in Access-Control-Allow-Origin lets any host become trusted — implement a strict allowlist instead."
}
func (corsReflectedCheck) RFCRefs() []string { return []string{"WHATWG Fetch §3.2"} }

func (corsReflectedCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCORSOriginReflected, checks.FamilyHTTP, checks.SeverityHigh, err), nil
	}
	if res.CORSReflect == nil || res.CORSReflect.Err != nil {
		reason := "CORS probe unreachable"
		if res.CORSReflect != nil && res.CORSReflect.Err != nil {
			reason = res.CORSReflect.Err.Error()
		}
		return skipped(IDCORSOriginReflected, checks.FamilyHTTP, checks.SeverityHigh, reason), nil
	}
	acao := strings.TrimSpace(res.CORSReflect.Headers.Get("Access-Control-Allow-Origin"))
	if acao == "https://websec0-test.invalid" {
		acac := strings.ToLower(strings.TrimSpace(res.CORSReflect.Headers.Get("Access-Control-Allow-Credentials")))
		sev := checks.SeverityMedium
		if acac == "true" {
			sev = checks.SeverityHigh
		}
		return fail(IDCORSOriginReflected, checks.FamilyHTTP, sev,
			"CORS reflects the Origin header",
			"Replace dynamic reflection with an allowlist of trusted origins.",
			map[string]any{"reflected": acao, "acac": acac}), nil
	}
	return pass(IDCORSOriginReflected, checks.FamilyHTTP, checks.SeverityHigh,
		"CORS does not reflect Origin",
		map[string]any{"acao": acao}), nil
}

// --- HTTP-CORS-NULL-ORIGIN -------------------------------------------
//
// `Origin: null` is sent by sandboxed iframes, data: URLs, and some file:
// loads — accepting it permits content-injection bypasses.

type corsNullCheck struct{}

func (corsNullCheck) ID() string                       { return IDCORSNullOrigin }
func (corsNullCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (corsNullCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (corsNullCheck) Title() string                    { return "CORS does not allow `null` origin" }
func (corsNullCheck) Description() string {
	return "Accepting `Access-Control-Allow-Origin: null` exposes the response to sandboxed iframes and data: URLs."
}
func (corsNullCheck) RFCRefs() []string { return []string{"WHATWG Fetch §3.2"} }

func (corsNullCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCORSNullOrigin, checks.FamilyHTTP, checks.SeverityHigh, err), nil
	}
	if res.CORSNull == nil || res.CORSNull.Err != nil {
		return skipped(IDCORSNullOrigin, checks.FamilyHTTP, checks.SeverityHigh, "CORS probe unreachable"), nil //nolint:nilerr // intentional
	}
	acao := strings.TrimSpace(res.CORSNull.Headers.Get("Access-Control-Allow-Origin"))
	if acao == "null" {
		return fail(IDCORSNullOrigin, checks.FamilyHTTP, checks.SeverityHigh,
			"CORS accepts `null` origin", "", nil), nil
	}
	return pass(IDCORSNullOrigin, checks.FamilyHTTP, checks.SeverityHigh,
		"CORS does not echo `null` origin",
		map[string]any{"acao": acao}), nil
}
