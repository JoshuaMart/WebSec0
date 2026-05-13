// Package headers fetches and evaluates the HTTP security headers exposed
// by a target. The package is split in four files:
// - parse.go — per-header tokenisers (HSTS, CSP, Set-Cookie, …)
// - core.go — evaluation of the 6 score-contributing headers
// - additional.go — bonus/malus signals (COOP/COEP/CORP, Server, cookies, …)
// - fetch.go — Fetch + Probe orchestrator
package headers

import (
	"strconv"
	"strings"
)

// HSTSDirectives is the parsed form of a Strict-Transport-Security value.
// MaxAge is -1 when the directive is absent or malformed.
type HSTSDirectives struct {
	MaxAge            int
	IncludeSubDomains bool
	Preload           bool
}

// ParseHSTS tokenises a Strict-Transport-Security header value.
func ParseHSTS(s string) HSTSDirectives {
	out := HSTSDirectives{MaxAge: -1}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(strings.ToLower(part), "max-age="):
			v := strings.TrimPrefix(strings.ToLower(part), "max-age=")
			v = strings.Trim(v, `"`)
			if n, err := strconv.Atoi(v); err == nil {
				out.MaxAge = n
			}
		case strings.EqualFold(part, "includeSubDomains"):
			out.IncludeSubDomains = true
		case strings.EqualFold(part, "preload"):
			out.Preload = true
		}
	}
	return out
}

// CSPInfo is the subset of CSP we use for scoring. We track unsafe-inline
// in script-src (and default-src as a fallback when script-src is absent),
// plus presence of frame-ancestors (covers X-Frame-Options).
type CSPInfo struct {
	HasScriptSrc        bool
	ScriptUnsafeInline  bool
	DefaultUnsafeInline bool
	HasFrameAncestors   bool
}

// ParseCSP tokenises a Content-Security-Policy header value.
func ParseCSP(s string) CSPInfo {
	directives := map[string][]string{}
	for _, d := range strings.Split(s, ";") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		parts := strings.Fields(d)
		name := strings.ToLower(parts[0])
		directives[name] = parts[1:]
	}
	info := CSPInfo{}
	if vals, ok := directives["script-src"]; ok {
		info.HasScriptSrc = true
		for _, v := range vals {
			if v == "'unsafe-inline'" {
				info.ScriptUnsafeInline = true
			}
		}
	}
	if vals, ok := directives["default-src"]; ok {
		for _, v := range vals {
			if v == "'unsafe-inline'" {
				info.DefaultUnsafeInline = true
			}
		}
	}
	if _, ok := directives["frame-ancestors"]; ok {
		info.HasFrameAncestors = true
	}
	return info
}

// CookieInfo is the parsed form of a single Set-Cookie value. SameSite is
// empty when the attribute is absent.
type CookieInfo struct {
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

// ParseCookie tokenises a Set-Cookie value. Attribute matching is case-insensitive.
func ParseCookie(s string) CookieInfo {
	info := CookieInfo{}
	parts := strings.Split(s, ";")
	if len(parts) == 0 {
		return info
	}
	nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	info.Name = nameValue[0]
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		lo := strings.ToLower(p)
		switch {
		case lo == "secure":
			info.Secure = true
		case lo == "httponly":
			info.HTTPOnly = true
		case strings.HasPrefix(lo, "samesite="):
			info.SameSite = strings.TrimSpace(p[len("samesite="):])
		}
	}
	return info
}

// ServerLeaksVersion is a heuristic that returns true if the Server header
// value contains a digit or a "/" — both strong signals that a software
// name + version is being advertised (e.g., "nginx/1.27.1").
func ServerLeaksVersion(s string) bool {
	return strings.ContainsAny(s, "0123456789/")
}

// IsACAOWildcard reports whether the Access-Control-Allow-Origin value is "*".
func IsACAOWildcard(s string) bool {
	return strings.TrimSpace(s) == "*"
}
