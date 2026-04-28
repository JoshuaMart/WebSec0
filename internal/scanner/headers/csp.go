package headers

import (
	"context"
	"strings"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// CSP is the parsed Content-Security-Policy. Directive names are
// lowercased; tokens preserve their original case (case-sensitive in CSP).
type CSP struct {
	Raw        string
	Directives map[string][]string
}

// ParseCSP returns nil when raw is empty. Multiple `;`-separated
// directives map onto one entry per name; a duplicate directive overrides
// per the spec — but we keep the first occurrence as the effective value
// (matches Chrome's behaviour and what `csp-evaluator` reports).
func ParseCSP(raw string) *CSP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := &CSP{Raw: raw, Directives: map[string][]string{}}
	for _, dir := range strings.Split(raw, ";") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		parts := strings.Fields(dir)
		if len(parts) == 0 {
			continue
		}
		name := strings.ToLower(parts[0])
		if _, exists := out.Directives[name]; exists {
			continue
		}
		out.Directives[name] = parts[1:]
	}
	return out
}

// fetchSourceList returns the effective tokens for directive after
// resolving the default-src fallback. Returns ("", nil) when nothing is
// declared and the directive does not fall back to default-src.
func (c *CSP) effective(directive string) []string {
	if c == nil {
		return nil
	}
	if v, ok := c.Directives[directive]; ok {
		return v
	}
	// CSP fetch directives that fall back to default-src.
	switch directive {
	case "script-src", "style-src", "img-src", "font-src", "connect-src",
		"media-src", "object-src", "frame-src", "child-src", "worker-src",
		"manifest-src", "prefetch-src":
		return c.Directives["default-src"]
	}
	return nil
}

func containsToken(tokens []string, want string) bool {
	for _, t := range tokens {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// --- HEADER-CSP-MISSING ----------------------------------------------

type cspMissingCheck struct{}

func (cspMissingCheck) ID() string                       { return IDCSPMissing }
func (cspMissingCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (cspMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (cspMissingCheck) Title() string                    { return "Content-Security-Policy is set" }
func (cspMissingCheck) Description() string {
	return "CSP (W3C CSP Level 3) is the strongest defence-in-depth against XSS and data exfiltration."
}
func (cspMissingCheck) RFCRefs() []string { return []string{"W3C CSP Level 3"} }

func (cspMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDCSPMissing, checks.SeverityMedium, err), nil
	}
	if !res.Reachable {
		return skippedFinding(IDCSPMissing, checks.SeverityMedium, "homepage unreachable"), nil
	}
	raw := res.Header("Content-Security-Policy")
	if raw == "" {
		f := failFinding(IDCSPMissing, checks.SeverityMedium,
			"no Content-Security-Policy header", "No Content-Security-Policy header was found in the HTTP response.",
			map[string]any{"value": ""})
		f.Remediation = map[string]any{
			"why_it_matters": "Content-Security-Policy restricts the origins from which scripts, styles, fonts, and other resources can load. It is the primary browser-enforced defence against Cross-Site Scripting (XSS).",
			"impact":         "Without CSP, any injected JavaScript executes with full page privileges — enabling session cookie theft, credential harvesting, cryptomining, and data exfiltration to attacker-controlled servers.",
			"references": []map[string]any{
				{"title": "MDN — Content-Security-Policy", "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"},
				{"title": "CSP Evaluator — Google", "url": "https://csp-evaluator.withgoogle.com/"},
				{"title": "OWASP CSP Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"},
			},
			"snippets": map[string]any{
				"nginx":   `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';" always;`,
				"apache":  `Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';"`,
				"caddy":   `header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';"`,
				"express": `app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'none'"] } }));`,
			},
			"verification": "curl -sI https://example.com | grep -i content-security-policy",
		}
		return f, nil
	}
	parsed := ParseCSP(raw)
	return passFinding(IDCSPMissing, checks.SeverityMedium,
		"CSP present",
		map[string]any{
			"raw":             raw,
			"directive_count": len(parsed.Directives),
			"directives":      cspDirectiveNames(parsed),
		}), nil
}

// cspDirectiveNames returns the directive keys sorted, used as
// evidence so the operator can scan what's present without parsing
// the raw header by eye.
func cspDirectiveNames(c *CSP) []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Directives))
	for k := range c.Directives {
		out = append(out, k)
	}
	// Stable order — alphabetical is fine since keys are normalised.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[i] > out[j] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// helper: shared lookup for CSP-derived checks
func loadCSP(ctx context.Context, t *checks.Target, id string, sev checks.Severity) (*CSP, *checks.Finding) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return nil, errFinding(id, sev, err)
	}
	if !res.Reachable {
		return nil, skippedFinding(id, sev, "homepage unreachable")
	}
	raw := res.Header("Content-Security-Policy")
	if raw == "" {
		return nil, skippedFinding(id, sev, "no CSP header")
	}
	return ParseCSP(raw), nil
}

// --- HEADER-CSP-UNSAFE-INLINE ----------------------------------------

type cspUnsafeInlineCheck struct{}

func (cspUnsafeInlineCheck) ID() string                       { return IDCSPUnsafeInline }
func (cspUnsafeInlineCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (cspUnsafeInlineCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (cspUnsafeInlineCheck) Title() string                    { return "CSP forbids 'unsafe-inline' for scripts" }
func (cspUnsafeInlineCheck) Description() string {
	return "Allowing 'unsafe-inline' in script-src defeats CSP's main XSS-protection purpose."
}
func (cspUnsafeInlineCheck) RFCRefs() []string { return []string{"W3C CSP Level 3"} }

func (cspUnsafeInlineCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	csp, skip := loadCSP(ctx, t, IDCSPUnsafeInline, checks.SeverityHigh)
	if skip != nil {
		return skip, nil
	}
	sources := csp.effective("script-src")
	ev := map[string]any{
		"directive": "script-src",
		"sources":   sources,
	}
	if containsToken(sources, "'unsafe-inline'") {
		return failFinding(IDCSPUnsafeInline, checks.SeverityHigh,
			"script-src allows 'unsafe-inline'",
			"Use nonces or hashes instead of 'unsafe-inline'.", ev), nil
	}
	return passFinding(IDCSPUnsafeInline, checks.SeverityHigh,
		"script-src does not allow 'unsafe-inline'", ev), nil
}

// --- HEADER-CSP-UNSAFE-EVAL ------------------------------------------

type cspUnsafeEvalCheck struct{}

func (cspUnsafeEvalCheck) ID() string                       { return IDCSPUnsafeEval }
func (cspUnsafeEvalCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (cspUnsafeEvalCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (cspUnsafeEvalCheck) Title() string                    { return "CSP forbids 'unsafe-eval'" }
func (cspUnsafeEvalCheck) Description() string {
	return "'unsafe-eval' enables eval() and Function() — a frequent XSS gadget."
}
func (cspUnsafeEvalCheck) RFCRefs() []string { return []string{"W3C CSP Level 3"} }

func (cspUnsafeEvalCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	csp, skip := loadCSP(ctx, t, IDCSPUnsafeEval, checks.SeverityHigh)
	if skip != nil {
		return skip, nil
	}
	sources := csp.effective("script-src")
	ev := map[string]any{
		"directive": "script-src",
		"sources":   sources,
	}
	if containsToken(sources, "'unsafe-eval'") {
		return failFinding(IDCSPUnsafeEval, checks.SeverityHigh,
			"script-src allows 'unsafe-eval'",
			"Refactor away from eval()/Function() and drop 'unsafe-eval'.", ev), nil
	}
	return passFinding(IDCSPUnsafeEval, checks.SeverityHigh,
		"script-src does not allow 'unsafe-eval'", ev), nil
}

// --- HEADER-CSP-WILDCARD-SRC -----------------------------------------

type cspWildcardCheck struct{}

func (cspWildcardCheck) ID() string                       { return IDCSPWildcardSrc }
func (cspWildcardCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (cspWildcardCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (cspWildcardCheck) Title() string                    { return "CSP avoids wildcard sources for active content" }
func (cspWildcardCheck) Description() string {
	return "default-src/script-src/connect-src with `*` defeats the policy."
}
func (cspWildcardCheck) RFCRefs() []string { return []string{"W3C CSP Level 3"} }

func (cspWildcardCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	csp, skip := loadCSP(ctx, t, IDCSPWildcardSrc, checks.SeverityMedium)
	if skip != nil {
		return skip, nil
	}
	dirsChecked := []string{"default-src", "script-src", "connect-src"}
	for _, dir := range dirsChecked {
		sources := csp.effective(dir)
		if containsToken(sources, "*") {
			return failFinding(IDCSPWildcardSrc, checks.SeverityMedium,
				"CSP uses wildcard `*` for "+dir,
				"Replace `*` with an explicit allowlist.",
				map[string]any{
					"directive": dir,
					"sources":   sources,
				}), nil
		}
	}
	return passFinding(IDCSPWildcardSrc, checks.SeverityMedium,
		"no wildcard in active-content directives",
		map[string]any{"directives_checked": dirsChecked}), nil
}

// --- HEADER-CSP-NO-OBJECT-SRC ----------------------------------------

type cspNoObjectSrcCheck struct{}

func (cspNoObjectSrcCheck) ID() string                       { return IDCSPNoObjectSrc }
func (cspNoObjectSrcCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (cspNoObjectSrcCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (cspNoObjectSrcCheck) Title() string                    { return "CSP restricts plugin sources" }
func (cspNoObjectSrcCheck) Description() string {
	return "Set `object-src 'none'` to disable Flash/Java/PDF embeds (or allow only what you need)."
}
func (cspNoObjectSrcCheck) RFCRefs() []string { return []string{"W3C CSP Level 3"} }

func (cspNoObjectSrcCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	csp, skip := loadCSP(ctx, t, IDCSPNoObjectSrc, checks.SeverityLow)
	if skip != nil {
		return skip, nil
	}
	tokens := csp.effective("object-src")
	if len(tokens) == 0 {
		_, hasDefault := csp.Directives["default-src"]
		return failFinding(IDCSPNoObjectSrc, checks.SeverityLow,
			"no object-src directive (and no default-src fallback)",
			"Add `object-src 'none';` to disable plugin embeds.",
			map[string]any{
				"directives_present": cspDirectiveNames(csp),
				"has_default_src":    hasDefault,
			}), nil
	}
	return passFinding(IDCSPNoObjectSrc, checks.SeverityLow,
		"object-src is restricted",
		map[string]any{"sources": tokens}), nil
}

// --- HEADER-CSP-NO-BASE-URI ------------------------------------------

type cspNoBaseURICheck struct{}

func (cspNoBaseURICheck) ID() string                       { return IDCSPNoBaseURI }
func (cspNoBaseURICheck) Family() checks.Family            { return checks.FamilyHeaders }
func (cspNoBaseURICheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (cspNoBaseURICheck) Title() string                    { return "CSP locks <base> elements" }
func (cspNoBaseURICheck) Description() string {
	return "Without `base-uri`, an injected <base> can hijack relative URLs."
}
func (cspNoBaseURICheck) RFCRefs() []string { return []string{"W3C CSP Level 3"} }

func (cspNoBaseURICheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	csp, skip := loadCSP(ctx, t, IDCSPNoBaseURI, checks.SeverityLow)
	if skip != nil {
		return skip, nil
	}
	v, ok := csp.Directives["base-uri"]
	if !ok {
		return failFinding(IDCSPNoBaseURI, checks.SeverityLow,
			"no base-uri directive",
			"Add `base-uri 'none'` or `base-uri 'self'`.",
			map[string]any{"directives_present": cspDirectiveNames(csp)}), nil
	}
	return passFinding(IDCSPNoBaseURI, checks.SeverityLow,
		"base-uri is set",
		map[string]any{"sources": v}), nil
}

// --- HEADER-CSP-NO-FRAME-ANCESTORS -----------------------------------

type cspNoFrameAncestorsCheck struct{}

func (cspNoFrameAncestorsCheck) ID() string                       { return IDCSPNoFrameAncestors }
func (cspNoFrameAncestorsCheck) Family() checks.Family            { return checks.FamilyHeaders }
func (cspNoFrameAncestorsCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (cspNoFrameAncestorsCheck) Title() string                    { return "CSP restricts framing" }
func (cspNoFrameAncestorsCheck) Description() string {
	return "frame-ancestors is the modern replacement for X-Frame-Options."
}
func (cspNoFrameAncestorsCheck) RFCRefs() []string { return []string{"W3C CSP Level 3"} }

func (cspNoFrameAncestorsCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	csp, skip := loadCSP(ctx, t, IDCSPNoFrameAncestors, checks.SeverityMedium)
	if skip != nil {
		return skip, nil
	}
	sources, ok := csp.Directives["frame-ancestors"]
	if !ok {
		return failFinding(IDCSPNoFrameAncestors, checks.SeverityMedium,
			"no frame-ancestors directive",
			"Add `frame-ancestors 'none'` (or 'self') unless you need cross-origin embedding.",
			map[string]any{"directives_present": cspDirectiveNames(csp)}), nil
	}
	return passFinding(IDCSPNoFrameAncestors, checks.SeverityMedium,
		"frame-ancestors is set",
		map[string]any{"sources": sources}), nil
}
