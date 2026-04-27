package cookies

import (
	"context"
	"net/http"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// Check IDs.
const (
	IDSecureMissing          = "COOKIE-SECURE-MISSING"
	IDHTTPOnlyMissingSession = "COOKIE-HTTPONLY-MISSING-SESSION"
	IDSameSiteMissing        = "COOKIE-SAMESITE-MISSING"
	IDSameSiteNoneNotSecure  = "COOKIE-SAMESITE-NONE-WITHOUT-SECURE"
	IDNoSecurityFlags        = "COOKIE-NO-SECURITY-FLAGS"
	IDPrefixSecureMissing    = "COOKIE-PREFIX-SECURE-MISSING"
	IDPrefixHostMissing      = "COOKIE-PREFIX-HOST-MISSING"
)

// Register adds every cookie check to r.
func Register(r *checks.Registry) {
	r.Register(secureMissingCheck{})
	r.Register(httpOnlyMissingSessionCheck{})
	r.Register(sameSiteMissingCheck{})
	r.Register(sameSiteNoneNotSecureCheck{})
	r.Register(noSecurityFlagsCheck{})
	r.Register(prefixSecureMissingCheck{})
	r.Register(prefixHostMissingCheck{})
}

// scanCookies is the shared preamble for every check: fetch, then act.
type scanFn func(cookies []*http.Cookie) *checks.Finding

func scanCookies(ctx context.Context, t *checks.Target, id string, sev checks.Severity, fn scanFn) *checks.Finding {
	cks, res, err := Cookies(ctx, t)
	if err != nil {
		return &checks.Finding{
			ID:          id,
			Family:      checks.FamilyCookies,
			Severity:    sev,
			Status:      checks.StatusError,
			Title:       "cookies: probe error",
			Description: err.Error(),
		}
	}
	if res == nil || !res.Reachable {
		return &checks.Finding{
			ID:       id,
			Family:   checks.FamilyCookies,
			Severity: sev,
			Status:   checks.StatusSkipped,
			Title:    "skipped: homepage unreachable",
		}
	}
	if len(cks) == 0 {
		return &checks.Finding{
			ID:       id,
			Family:   checks.FamilyCookies,
			Severity: sev,
			Status:   checks.StatusSkipped,
			Title:    "skipped: no cookies set",
		}
	}
	return fn(cks)
}

func cookieNames(cks []*http.Cookie) []string {
	out := make([]string, 0, len(cks))
	for _, c := range cks {
		out = append(out, c.Name)
	}
	return out
}

func passF(id string, sev checks.Severity, title string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyCookies, Severity: sev,
		Status: checks.StatusPass, Title: title, Evidence: ev,
	}
}

func failF(id string, sev checks.Severity, title, desc string, ev map[string]any) *checks.Finding {
	return &checks.Finding{
		ID: id, Family: checks.FamilyCookies, Severity: sev,
		Status: checks.StatusFail, Title: title, Description: desc, Evidence: ev,
	}
}

// --- COOKIE-SECURE-MISSING -------------------------------------------

type secureMissingCheck struct{}

func (secureMissingCheck) ID() string                       { return IDSecureMissing }
func (secureMissingCheck) Family() checks.Family            { return checks.FamilyCookies }
func (secureMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (secureMissingCheck) Title() string                    { return "All cookies carry Secure" }
func (secureMissingCheck) Description() string {
	return "Cookies without Secure are sent on plain HTTP and can be sniffed off the wire."
}
func (secureMissingCheck) RFCRefs() []string { return []string{"RFC 6265bis"} }

func (secureMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return scanCookies(ctx, t, IDSecureMissing, checks.SeverityMedium, func(cks []*http.Cookie) *checks.Finding {
		var bad []string
		for _, c := range cks {
			if !HasSecure(c) {
				bad = append(bad, c.Name)
			}
		}
		if len(bad) > 0 {
			f := failF(IDSecureMissing, checks.SeverityMedium,
				"cookies missing Secure flag",
				"Add `Secure` to every Set-Cookie served on HTTPS.",
				map[string]any{"names": bad})
			f.Remediation = map[string]any{
				"why_it_matters": "The Secure flag prevents cookies from being transmitted over unencrypted HTTP connections. Even on HTTPS-only sites, mixed-content or misconfigured redirects can expose cookies without this flag.",
				"impact":         "Session cookies sent over HTTP can be intercepted by network attackers, enabling session hijacking and account takeover. Particularly dangerous on public Wi-Fi.",
				"references": []map[string]any{
					{"title": "MDN — Set-Cookie: Secure", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure"},
					{"title": "OWASP — Session Management Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"},
				},
				"snippets": map[string]any{
					"express": `res.cookie('session', value, { secure: true, httpOnly: true, sameSite: 'strict' });`,
					"spring":  "server.servlet.session.cookie.secure=true",
					"nginx":   "# Set the Secure flag in your application, not at the proxy level.",
				},
				"verification": "curl -sI https://example.com | grep -i set-cookie",
			}
			return f
		}
		return passF(IDSecureMissing, checks.SeverityMedium,
			"every cookie has Secure",
			map[string]any{"count": len(cks)})
	}), nil
}

// --- COOKIE-HTTPONLY-MISSING-SESSION ---------------------------------

type httpOnlyMissingSessionCheck struct{}

func (httpOnlyMissingSessionCheck) ID() string                       { return IDHTTPOnlyMissingSession }
func (httpOnlyMissingSessionCheck) Family() checks.Family            { return checks.FamilyCookies }
func (httpOnlyMissingSessionCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (httpOnlyMissingSessionCheck) Title() string                    { return "Session cookies are HttpOnly" }
func (httpOnlyMissingSessionCheck) Description() string {
	return "Without HttpOnly, an XSS payload can read the session cookie via document.cookie."
}
func (httpOnlyMissingSessionCheck) RFCRefs() []string { return []string{"RFC 6265bis"} }

func (httpOnlyMissingSessionCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return scanCookies(ctx, t, IDHTTPOnlyMissingSession, checks.SeverityHigh, func(cks []*http.Cookie) *checks.Finding {
		var session []string
		var bad []string
		for _, c := range cks {
			if !IsSessionCookie(c.Name) {
				continue
			}
			session = append(session, c.Name)
			if !HasHTTPOnly(c) {
				bad = append(bad, c.Name)
			}
		}
		if len(session) == 0 {
			return &checks.Finding{
				ID: IDHTTPOnlyMissingSession, Family: checks.FamilyCookies,
				Severity: checks.SeverityHigh, Status: checks.StatusSkipped,
				Title: "no cookie matched the session-name heuristic",
			}
		}
		if len(bad) > 0 {
			return failF(IDHTTPOnlyMissingSession, checks.SeverityHigh,
				"session cookies missing HttpOnly",
				"Add `HttpOnly` to every session-class cookie.",
				map[string]any{"names": bad})
		}
		return passF(IDHTTPOnlyMissingSession, checks.SeverityHigh,
			"every session cookie has HttpOnly",
			map[string]any{"sessions": session})
	}), nil
}

// --- COOKIE-SAMESITE-MISSING -----------------------------------------

type sameSiteMissingCheck struct{}

func (sameSiteMissingCheck) ID() string                       { return IDSameSiteMissing }
func (sameSiteMissingCheck) Family() checks.Family            { return checks.FamilyCookies }
func (sameSiteMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (sameSiteMissingCheck) Title() string                    { return "Cookies declare SameSite explicitly" }
func (sameSiteMissingCheck) Description() string {
	return "Without an explicit SameSite, browser defaults vary across vendors and versions."
}
func (sameSiteMissingCheck) RFCRefs() []string { return []string{"RFC 6265bis §4.1.2.7"} }

func (sameSiteMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return scanCookies(ctx, t, IDSameSiteMissing, checks.SeverityMedium, func(cks []*http.Cookie) *checks.Finding {
		var bad []string
		for _, c := range cks {
			if !SameSiteSet(c) {
				bad = append(bad, c.Name)
			}
		}
		if len(bad) > 0 {
			f := failF(IDSameSiteMissing, checks.SeverityMedium,
				"cookies missing SameSite attribute",
				"Add `SameSite=Lax` (or `Strict`) to every cookie.",
				map[string]any{"names": bad})
			f.Remediation = map[string]any{
				"why_it_matters": "SameSite controls whether cookies are sent with cross-site requests. Without it, browsers fall back to legacy behaviour that allows cookies on cross-origin navigations, enabling CSRF attacks.",
				"impact":         "Attackers can trick authenticated users into performing unintended actions — fund transfers, password changes, settings modifications — by embedding cross-origin requests on attacker-controlled pages.",
				"references": []map[string]any{
					{"title": "MDN — SameSite cookies", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"},
					{"title": "OWASP — CSRF Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
				},
				"snippets": map[string]any{
					"express": `res.cookie('session', value, { sameSite: 'strict' });`,
					"spring":  "server.servlet.session.cookie.same-site=strict",
				},
				"verification": "curl -sI https://example.com | grep -i samesite",
			}
			return f
		}
		return passF(IDSameSiteMissing, checks.SeverityMedium,
			"every cookie carries an explicit SameSite", nil)
	}), nil
}

// --- COOKIE-SAMESITE-NONE-WITHOUT-SECURE -----------------------------

type sameSiteNoneNotSecureCheck struct{}

func (sameSiteNoneNotSecureCheck) ID() string                       { return IDSameSiteNoneNotSecure }
func (sameSiteNoneNotSecureCheck) Family() checks.Family            { return checks.FamilyCookies }
func (sameSiteNoneNotSecureCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (sameSiteNoneNotSecureCheck) Title() string                    { return "SameSite=None cookies also carry Secure" }
func (sameSiteNoneNotSecureCheck) Description() string {
	return "Per RFC 6265bis §4.1.2.7 a `SameSite=None` cookie MUST be Secure; Chrome refuses otherwise."
}
func (sameSiteNoneNotSecureCheck) RFCRefs() []string { return []string{"RFC 6265bis §4.1.2.7"} }

func (sameSiteNoneNotSecureCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return scanCookies(ctx, t, IDSameSiteNoneNotSecure, checks.SeverityMedium, func(cks []*http.Cookie) *checks.Finding {
		var bad []string
		var hasNone bool
		for _, c := range cks {
			if c.SameSite == http.SameSiteNoneMode {
				hasNone = true
			}
			if SameSiteNoneWithoutSecure(c) {
				bad = append(bad, c.Name)
			}
		}
		if !hasNone {
			return &checks.Finding{
				ID: IDSameSiteNoneNotSecure, Family: checks.FamilyCookies,
				Severity: checks.SeverityMedium, Status: checks.StatusSkipped,
				Title: "no SameSite=None cookies",
			}
		}
		if len(bad) > 0 {
			return failF(IDSameSiteNoneNotSecure, checks.SeverityMedium,
				"SameSite=None cookies missing Secure",
				"Either drop SameSite=None or add Secure.",
				map[string]any{"names": bad})
		}
		return passF(IDSameSiteNoneNotSecure, checks.SeverityMedium,
			"all SameSite=None cookies are Secure", nil)
	}), nil
}

// --- COOKIE-NO-SECURITY-FLAGS ----------------------------------------

type noSecurityFlagsCheck struct{}

func (noSecurityFlagsCheck) ID() string                       { return IDNoSecurityFlags }
func (noSecurityFlagsCheck) Family() checks.Family            { return checks.FamilyCookies }
func (noSecurityFlagsCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (noSecurityFlagsCheck) Title() string                    { return "Every cookie has at least one security flag" }
func (noSecurityFlagsCheck) Description() string {
	return "A cookie with no Secure / HttpOnly / SameSite is the worst-case (sniffable, JS-readable, CSRF-prone)."
}
func (noSecurityFlagsCheck) RFCRefs() []string { return []string{"RFC 6265bis"} }

func (noSecurityFlagsCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return scanCookies(ctx, t, IDNoSecurityFlags, checks.SeverityMedium, func(cks []*http.Cookie) *checks.Finding {
		var bad []string
		for _, c := range cks {
			if !HasAnySecurityFlag(c) {
				bad = append(bad, c.Name)
			}
		}
		if len(bad) > 0 {
			f := failF(IDNoSecurityFlags, checks.SeverityMedium,
				"cookies with no security flags at all",
				"Set at least Secure + SameSite, plus HttpOnly for sessions.",
				map[string]any{"names": bad})
			f.Remediation = map[string]any{
				"why_it_matters": "A cookie with no security flags is simultaneously vulnerable to three attack classes: network interception (no Secure), JavaScript theft via XSS (no HttpOnly), and cross-site request forgery (no SameSite).",
				"impact":         "Any single attack vector — XSS, man-in-the-middle, or CSRF — is sufficient to compromise the affected sessions. Combining all three makes exploitation trivial.",
				"references": []map[string]any{
					{"title": "OWASP — Testing for Cookies Attributes", "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"},
				},
				"snippets": map[string]any{
					"express": `res.cookie('session', value, { secure: true, httpOnly: true, sameSite: 'strict' });`,
					"spring":  "server.servlet.session.cookie.secure=true\nserver.servlet.session.cookie.http-only=true\nserver.servlet.session.cookie.same-site=strict",
				},
				"verification": "curl -sI https://example.com | grep -i set-cookie",
			}
			return f
		}
		return passF(IDNoSecurityFlags, checks.SeverityMedium,
			"every cookie has at least one security flag",
			map[string]any{"all": cookieNames(cks)})
	}), nil
}

// --- COOKIE-PREFIX-SECURE-MISSING ------------------------------------

type prefixSecureMissingCheck struct{}

func (prefixSecureMissingCheck) ID() string                       { return IDPrefixSecureMissing }
func (prefixSecureMissingCheck) Family() checks.Family            { return checks.FamilyCookies }
func (prefixSecureMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (prefixSecureMissingCheck) Title() string                    { return "Session cookies use the __Secure- prefix" }
func (prefixSecureMissingCheck) Description() string {
	return "The `__Secure-` prefix forbids the cookie from being set without Secure (defence-in-depth)."
}
func (prefixSecureMissingCheck) RFCRefs() []string { return []string{"RFC 6265bis §4.1.3.1"} }

func (prefixSecureMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return scanCookies(ctx, t, IDPrefixSecureMissing, checks.SeverityLow, func(cks []*http.Cookie) *checks.Finding {
		var session, bad []string
		for _, c := range cks {
			if !IsSessionCookie(c.Name) {
				continue
			}
			session = append(session, c.Name)
			if !strings.HasPrefix(c.Name, "__Secure-") && !strings.HasPrefix(c.Name, "__Host-") {
				bad = append(bad, c.Name)
			}
		}
		if len(session) == 0 {
			return &checks.Finding{
				ID: IDPrefixSecureMissing, Family: checks.FamilyCookies,
				Severity: checks.SeverityLow, Status: checks.StatusSkipped,
				Title: "no session-class cookies",
			}
		}
		if len(bad) > 0 {
			return failF(IDPrefixSecureMissing, checks.SeverityLow,
				"session cookies without `__Secure-` (or `__Host-`) prefix",
				"Rename to `__Secure-<name>` to opt into the cookie-prefix protection.",
				map[string]any{"names": bad})
		}
		return passF(IDPrefixSecureMissing, checks.SeverityLow,
			"every session cookie uses a secure prefix", nil)
	}), nil
}

// --- COOKIE-PREFIX-HOST-MISSING --------------------------------------

type prefixHostMissingCheck struct{}

func (prefixHostMissingCheck) ID() string                       { return IDPrefixHostMissing }
func (prefixHostMissingCheck) Family() checks.Family            { return checks.FamilyCookies }
func (prefixHostMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (prefixHostMissingCheck) Title() string                    { return "Session cookies use the __Host- prefix" }
func (prefixHostMissingCheck) Description() string {
	return "`__Host-` is stricter than `__Secure-`: it pins the cookie to the exact host (no Domain attribute)."
}
func (prefixHostMissingCheck) RFCRefs() []string { return []string{"RFC 6265bis §4.1.3.2"} }

func (prefixHostMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	return scanCookies(ctx, t, IDPrefixHostMissing, checks.SeverityLow, func(cks []*http.Cookie) *checks.Finding {
		var session, bad []string
		for _, c := range cks {
			if !IsSessionCookie(c.Name) {
				continue
			}
			session = append(session, c.Name)
			if !strings.HasPrefix(c.Name, "__Host-") {
				bad = append(bad, c.Name)
			}
		}
		if len(session) == 0 {
			return &checks.Finding{
				ID: IDPrefixHostMissing, Family: checks.FamilyCookies,
				Severity: checks.SeverityLow, Status: checks.StatusSkipped,
				Title: "no session-class cookies",
			}
		}
		if len(bad) > 0 {
			return failF(IDPrefixHostMissing, checks.SeverityLow,
				"session cookies without `__Host-` prefix",
				"`__Host-` is the strictest opt-in; consider it for top-tier session cookies.",
				map[string]any{"names": bad})
		}
		return passF(IDPrefixHostMissing, checks.SeverityLow,
			"every session cookie uses the __Host- prefix", nil)
	}), nil
}
