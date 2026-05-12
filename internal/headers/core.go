package headers

import (
	"net/http"
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// MinHSTSMaxAge is the threshold below which HSTS is considered weak (in seconds).
const MinHSTSMaxAge = 31536000 // one year

// CoreHeaderNames lists the six score-contributing headers in stable order
// (SPEC §4.2).
var CoreHeaderNames = []string{
	"strict-transport-security",
	"content-security-policy",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
}

// EvaluateCore returns one HeaderResult per core header. Map keys match
// SPEC §6.5 (lowercase header names).
func EvaluateCore(h http.Header) map[string]scan.HeaderResult {
	return map[string]scan.HeaderResult{
		"strict-transport-security": evalHSTS(h.Get("Strict-Transport-Security")),
		"content-security-policy":   evalCSP(h.Get("Content-Security-Policy")),
		"x-frame-options":           evalXFO(h),
		"x-content-type-options":    evalXCTO(h.Get("X-Content-Type-Options")),
		"referrer-policy":           evalReferrerPolicy(h.Get("Referrer-Policy")),
		"permissions-policy":        evalPermissionsPolicy(h.Get("Permissions-Policy")),
	}
}

func evalHSTS(v string) scan.HeaderResult {
	if v == "" {
		return scan.HeaderResult{Present: false, Status: scan.StatusFail}
	}
	p := ParseHSTS(v)
	if p.MaxAge < MinHSTSMaxAge {
		return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusWarn}
	}
	if !p.IncludeSubDomains {
		return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusWarn}
	}
	return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
}

func evalCSP(v string) scan.HeaderResult {
	if v == "" {
		return scan.HeaderResult{Present: false, Status: scan.StatusFail}
	}
	info := ParseCSP(v)
	if info.ScriptUnsafeInline {
		return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusWarn}
	}
	if !info.HasScriptSrc && info.DefaultUnsafeInline {
		return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusWarn}
	}
	return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
}

// evalXFO accepts DENY/SAMEORIGIN, falls back to a passing status if
// Content-Security-Policy includes frame-ancestors (which supersedes XFO
// in modern browsers).
func evalXFO(h http.Header) scan.HeaderResult {
	v := h.Get("X-Frame-Options")
	if v != "" {
		u := strings.ToUpper(strings.TrimSpace(v))
		if u == "DENY" || u == "SAMEORIGIN" {
			return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
		}
		return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusWarn}
	}
	if csp := h.Get("Content-Security-Policy"); csp != "" {
		if ParseCSP(csp).HasFrameAncestors {
			return scan.HeaderResult{Present: false, Status: scan.StatusPass}
		}
	}
	return scan.HeaderResult{Present: false, Status: scan.StatusFail}
}

func evalXCTO(v string) scan.HeaderResult {
	if v == "" {
		return scan.HeaderResult{Present: false, Status: scan.StatusFail}
	}
	if strings.EqualFold(strings.TrimSpace(v), "nosniff") {
		return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
	}
	return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusWarn}
}

// permissiveReferrer lists Referrer-Policy values that leak too much.
var permissiveReferrer = map[string]bool{
	"":                           true,
	"unsafe-url":                 true,
	"no-referrer-when-downgrade": true,
}

func evalReferrerPolicy(v string) scan.HeaderResult {
	if v == "" {
		return scan.HeaderResult{Present: false, Status: scan.StatusFail}
	}
	if permissiveReferrer[strings.ToLower(strings.TrimSpace(v))] {
		return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusWarn}
	}
	return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
}

func evalPermissionsPolicy(v string) scan.HeaderResult {
	if v == "" {
		return scan.HeaderResult{Present: false, Status: scan.StatusFail}
	}
	return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
}
