package headers

import (
	"net/http"
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// EvaluateAdditional inspects the bonus/malus headers and returns the
// AdditionalHeaders shape (SPEC §6.5). All fields are pointers so they
// can be omitted from the JSON output when absent.
func EvaluateAdditional(h http.Header) scan.AdditionalHeaders {
	out := scan.AdditionalHeaders{}

	if v := h.Get("Server"); v != "" {
		out.Server = serverResult(v)
	}
	if v := h.Get("Cross-Origin-Opener-Policy"); v != "" {
		out.CrossOriginOpenerPolicy = coopResult(v)
	}
	if v := h.Get("Cross-Origin-Embedder-Policy"); v != "" {
		out.CrossOriginEmbedderPolicy = simpleAdditional(v)
	}
	if v := h.Get("Cross-Origin-Resource-Policy"); v != "" {
		out.CrossOriginResourcePolicy = simpleAdditional(v)
	}
	if vs := h.Values("Set-Cookie"); len(vs) > 0 {
		out.SetCookie = evaluateCookies(vs)
	}
	if v := h.Get("Access-Control-Allow-Origin"); v != "" {
		out.AccessControlAllowOrigin = acaoResult(v)
	}
	return out
}

func serverResult(v string) *scan.HeaderResult {
	status := scan.StatusInfo
	if ServerLeaksVersion(v) {
		status = scan.StatusWarn
	}
	return &scan.HeaderResult{Present: true, Value: v, Status: status}
}

func coopResult(v string) *scan.HeaderResult {
	status := scan.StatusWarn
	if strings.EqualFold(strings.TrimSpace(v), "same-origin") {
		status = scan.StatusPass
	}
	return &scan.HeaderResult{Present: true, Value: v, Status: status}
}

func simpleAdditional(v string) *scan.HeaderResult {
	return &scan.HeaderResult{Present: true, Value: v, Status: scan.StatusPass}
}

func acaoResult(v string) *scan.HeaderResult {
	status := scan.StatusInfo
	if IsACAOWildcard(v) {
		status = scan.StatusWarn
	}
	return &scan.HeaderResult{Present: true, Value: v, Status: status}
}

func evaluateCookies(raws []string) []scan.CookieResult {
	out := make([]scan.CookieResult, 0, len(raws))
	for _, raw := range raws {
		ci := ParseCookie(raw)
		var sameSite *string
		if ci.SameSite != "" {
			s := ci.SameSite
			sameSite = &s
		}
		cookie := scan.CookieResult{
			Name:     ci.Name,
			Secure:   ci.Secure,
			HTTPOnly: ci.HTTPOnly,
			SameSite: sameSite,
			Status:   cookieStatus(ci),
		}
		out = append(out, cookie)
	}
	return out
}

func cookieStatus(c CookieInfo) scan.Status {
	if !c.Secure {
		return scan.StatusFail
	}
	if c.SameSite == "" {
		return scan.StatusWarn
	}
	if !c.HTTPOnly && LooksLikeSession(c.Name) {
		return scan.StatusWarn
	}
	return scan.StatusPass
}

// sessionNameHints is the closed set of substrings that flag a cookie as
// session-bearing for the purpose of HttpOnly checks. Lowercase, no spaces.
var sessionNameHints = []string{"session", "auth", "token", "sid", "jwt", "csrf"}

// LooksLikeSession is exported so the scoring engine can apply the same
// heuristic when computing the HttpOnly malus.
func LooksLikeSession(name string) bool {
	lower := strings.ToLower(name)
	for _, h := range sessionNameHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}
