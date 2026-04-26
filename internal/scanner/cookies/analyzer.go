// Package cookies implements the cookie-hardening family of checks. It
// reuses the homepage fetch performed by internal/scanner/headers.
package cookies

import (
	"context"
	"net/http"
	"strings"

	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/scanner/headers"
)

// Cookies returns every cookie set on the homepage response.
func Cookies(ctx context.Context, t *checks.Target) ([]*http.Cookie, *headers.FetchResult, error) {
	res, err := headers.Fetch(ctx, t)
	if err != nil {
		return nil, nil, err
	}
	if !res.Reachable {
		return nil, res, nil
	}
	resp := &http.Response{Header: res.Headers}
	return resp.Cookies(), res, nil
}

// IsSessionCookie applies a name-based heuristic — the same one used by
// every off-the-shelf scanner. False positives are acceptable (we just
// hold those cookies to a higher bar); false negatives are tolerable
// because the SECURE / SAMESITE checks still fire on them.
func IsSessionCookie(name string) bool {
	n := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(name, "__Secure-"), "__Host-"))
	if strings.Contains(n, "session") || strings.Contains(n, "sessid") ||
		strings.Contains(n, "sess_") || strings.Contains(n, "sess-") {
		return true
	}
	switch n {
	case "sid",
		"phpsessid",
		"jsessionid",
		"asp.net_sessionid",
		"connect.sid",
		"_session_id",
		"auth",
		"auth_token",
		"authtoken",
		"auth-token",
		"access_token",
		"refresh_token",
		"csrf_token",
		"xsrf-token",
		"_csrf":
		return true
	}
	return false
}

// HasSecure / HasHTTPOnly / SameSiteAttr are tiny wrappers that make the
// check methods read like prose.
func HasSecure(c *http.Cookie) bool   { return c.Secure }
func HasHTTPOnly(c *http.Cookie) bool { return c.HttpOnly }

// SameSiteSet returns true when the cookie carries a SameSite attribute.
//
// Counter-intuitively, http.SameSiteDefaultMode is *not* the absent
// sentinel — Go's iota starts at 1 for that const, so an unset SameSite
// is the zero value (0). Comparing against the literal zero is the
// correct way to detect "no attribute".
func SameSiteSet(c *http.Cookie) bool { return c.SameSite != 0 }

// SameSiteNoneWithoutSecure flags the spec violation Chrome blocks.
func SameSiteNoneWithoutSecure(c *http.Cookie) bool {
	return c.SameSite == http.SameSiteNoneMode && !c.Secure
}

// HasAnySecurityFlag is the inverse of "no security flags at all".
func HasAnySecurityFlag(c *http.Cookie) bool {
	return c.Secure || c.HttpOnly || SameSiteSet(c)
}
