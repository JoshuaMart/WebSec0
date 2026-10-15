package headers

import (
	"net/http"
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// MinHSTSMaxAge is the threshold below which HSTS is considered weak (in seconds).
const MinHSTSMaxAge = 31536000 // one year

// CoreHeaderNames lists the six score-contributing headers in stable order
var CoreHeaderNames = []string{
	"strict-transport-security",
	"content-security-policy",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
}

// EvaluateCore returns one HeaderResult per core header. Map keys match
// (lowercase header names).
func EvaluateCore(h http.Header) map[string]scan.HeaderResult {
	return map[string]scan.HeaderResult{
		"strict-transport-security": evalHSTS(h.Get("Strict-Transport-Security")),
		"content-security-policy":   evalCSP(h.Get("Content-Security-Policy")),
		"x-frame-options":           evalXFO(h),
		"x-content-type-options":    evalXCTO(h.Get("X-Content-Type-Options")),
		"referrer-policy":           evalReferrerPolicy(h),
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

// evalXFO follows the HTML Standard's X-Frame-Options processing model. An
// enforced CSP with frame-ancestors makes browsers ignore XFO entirely, so it
// passes whatever XFO says. Otherwise every XFO value, across header lines and
// comma-separated lists, is collected: a lone DENY or SAMEORIGIN passes;
// conflicting values make browsers block framing everywhere, which protects
// but breaks same-origin frames (warn); a lone invalid value such as
// ALLOW-FROM is ignored by browsers and fails like a missing header.
func evalXFO(h http.Header) scan.HeaderResult {
	raw := strings.Join(h.Values("X-Frame-Options"), ", ")
	present := strings.TrimSpace(raw) != ""
	res := scan.HeaderResult{Present: present, Status: scan.StatusFail}
	if present {
		res.Value = raw
	}
	if hasFrameAncestors(h) {
		res.Status = scan.StatusPass
		return res
	}
	if !present {
		return res
	}
	values := map[string]bool{}
	for _, v := range strings.Split(raw, ",") {
		values[strings.ToLower(strings.Trim(v, " \t"))] = true
	}
	if len(values) > 1 {
		if values["deny"] || values["sameorigin"] || values["allowall"] {
			res.Status = scan.StatusWarn
		}
		return res
	}
	if values["deny"] || values["sameorigin"] {
		res.Status = scan.StatusPass
	}
	return res
}

// hasFrameAncestors reports whether any Content-Security-Policy in the
// response sets frame-ancestors. Browsers enforce every policy, whether sent
// as separate header lines or as a comma-separated list in one line.
func hasFrameAncestors(h http.Header) bool {
	for _, line := range h.Values("Content-Security-Policy") {
		for _, policy := range strings.Split(line, ",") {
			if ParseCSP(policy).HasFrameAncestors {
				return true
			}
		}
	}
	return false
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

// referrerPolicies lists the values defined by the Referrer Policy spec.
var referrerPolicies = map[string]bool{
	"no-referrer":                     true,
	"no-referrer-when-downgrade":      true,
	"same-origin":                     true,
	"origin":                          true,
	"strict-origin":                   true,
	"origin-when-cross-origin":        true,
	"strict-origin-when-cross-origin": true,
	"unsafe-url":                      true,
}

// permissiveReferrer lists Referrer-Policy values that leak too much.
var permissiveReferrer = map[string]bool{
	"unsafe-url":                 true,
	"no-referrer-when-downgrade": true,
}

// evalReferrerPolicy grades the policy browsers apply: the last recognised
// value across all header lines and comma-separated lists (Referrer Policy
// §8.1). Unknown values are skipped, as browsers do; a header with no
// recognised value leaves the browser default in place and fails like a
// missing one.
func evalReferrerPolicy(h http.Header) scan.HeaderResult {
	raw := strings.Join(h.Values("Referrer-Policy"), ", ")
	if strings.TrimSpace(raw) == "" {
		return scan.HeaderResult{Present: false, Status: scan.StatusFail}
	}
	policy := ""
	for _, v := range strings.Split(raw, ",") {
		if v = strings.ToLower(strings.Trim(v, " \t")); referrerPolicies[v] {
			policy = v
		}
	}
	res := scan.HeaderResult{Present: true, Value: raw, Status: scan.StatusPass}
	switch {
	case policy == "":
		res.Status = scan.StatusFail
	case permissiveReferrer[policy]:
		res.Status = scan.StatusWarn
	}
	return res
}

func evalPermissionsPolicy(v string) scan.HeaderResult {
	if v == "" {
		return scan.HeaderResult{Present: false, Status: scan.StatusFail}
	}
	return scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
}
