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

// PermissionsAllowlist is the allowlist a browser builds for one feature of a
// Permissions-Policy (Permissions Policy §9.2).
type PermissionsAllowlist struct {
	All     bool     // * alone or in the list
	Self    bool     // self alone or in the list
	Origins []string // strings in the list
}

// Disabled reports whether the allowlist matches no origin at all, as with
// feature=(). Tokens other than * and self are ignored by browsers, so
// feature=none is disabled too.
func (a PermissionsAllowlist) Disabled() bool {
	return !a.All && !a.Self && len(a.Origins) == 0
}

// ParsePermissionsPolicy parses a Permissions-Policy value as a Structured
// Field dictionary (RFC 9651), as browsers do; join several field lines with
// ", " first. ok is false when the value does not parse, in which case
// browsers ignore the whole header. A feature defined twice keeps its last
// definition.
func ParsePermissionsPolicy(s string) (policy map[string]PermissionsAllowlist, ok bool) {
	dict, ok := parseSFDictionary(s)
	if !ok {
		return nil, false
	}
	policy = make(map[string]PermissionsAllowlist, len(dict))
	for feature, m := range dict {
		var a PermissionsAllowlist
		if !m.list {
			a.All = m.item.isToken("*")
			a.Self = m.item.isToken("self")
		}
		for _, it := range m.items {
			switch {
			case it.isToken("*"):
				a.All = true
			case it.isToken("self"):
				a.Self = true
			case it.kind == sfString:
				a.Origins = append(a.Origins, it.val)
			}
		}
		policy[feature] = a
	}
	return policy, true
}

// Structured Field parsing (RFC 9651 §4.2), limited to what dictionaries
// need: values are kept only for tokens and strings, other bare items are
// validated and discarded.

type sfKind int

const (
	sfOther sfKind = iota
	sfToken
	sfString
)

type sfItem struct {
	kind sfKind
	val  string
}

func (it sfItem) isToken(v string) bool { return it.kind == sfToken && it.val == v }

type sfMember struct {
	list  bool
	item  sfItem   // when !list
	items []sfItem // when list
}

type sfParser struct {
	s string
	i int
}

func (p *sfParser) eof() bool { return p.i >= len(p.s) }

func (p *sfParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}

func (p *sfParser) skipSP() {
	for p.peek() == ' ' {
		p.i++
	}
}

func (p *sfParser) skipOWS() {
	for p.peek() == ' ' || p.peek() == '\t' {
		p.i++
	}
}

func parseSFDictionary(s string) (map[string]sfMember, bool) {
	p := &sfParser{s: strings.Trim(s, " ")}
	out := map[string]sfMember{}
	for !p.eof() {
		key, ok := p.key()
		if !ok {
			return nil, false
		}
		var m sfMember
		if p.peek() == '=' {
			p.i++
			if m, ok = p.member(); !ok {
				return nil, false
			}
		} else if !p.params() { // a bare key is Boolean true
			return nil, false
		}
		out[key] = m
		p.skipOWS()
		if p.eof() {
			break
		}
		if p.peek() != ',' {
			return nil, false
		}
		p.i++
		p.skipOWS()
		if p.eof() { // trailing comma
			return nil, false
		}
	}
	return out, true
}

func (p *sfParser) member() (sfMember, bool) {
	if p.peek() != '(' {
		it, ok := p.item()
		return sfMember{item: it}, ok
	}
	p.i++
	m := sfMember{list: true}
	for !p.eof() {
		p.skipSP()
		if p.peek() == ')' {
			p.i++
			return m, p.params()
		}
		it, ok := p.item()
		if !ok {
			return m, false
		}
		m.items = append(m.items, it)
		if c := p.peek(); c != ' ' && c != ')' {
			return m, false
		}
	}
	return m, false
}

func (p *sfParser) item() (sfItem, bool) {
	it, ok := p.bareItem()
	return it, ok && p.params()
}

func (p *sfParser) params() bool {
	for p.peek() == ';' {
		p.i++
		p.skipSP()
		if _, ok := p.key(); !ok {
			return false
		}
		if p.peek() == '=' {
			p.i++
			if _, ok := p.bareItem(); !ok {
				return false
			}
		}
	}
	return true
}

func (p *sfParser) key() (string, bool) {
	start := p.i
	if c := p.peek(); !isLCAlpha(c) && c != '*' {
		return "", false
	}
	for !p.eof() {
		c := p.peek()
		if !isLCAlpha(c) && !isDigit(c) && !strings.ContainsRune("_-.*", rune(c)) {
			break
		}
		p.i++
	}
	return p.s[start:p.i], true
}

func (p *sfParser) bareItem() (sfItem, bool) {
	switch c := p.peek(); {
	case c == '-' || isDigit(c):
		return sfItem{}, p.number()
	case c == '"':
		return p.str()
	case c == '*' || isAlpha(c):
		start := p.i
		p.i++
		for !p.eof() && (isTChar(p.peek()) || p.peek() == ':' || p.peek() == '/') {
			p.i++
		}
		return sfItem{kind: sfToken, val: p.s[start:p.i]}, true
	case c == ':':
		p.i++
		for !p.eof() && p.peek() != ':' {
			if !isAlpha(p.peek()) && !isDigit(p.peek()) && !strings.ContainsRune("+/=", rune(p.peek())) {
				return sfItem{}, false
			}
			p.i++
		}
		if p.eof() {
			return sfItem{}, false
		}
		p.i++
		return sfItem{}, true
	case c == '?':
		p.i++
		if c := p.peek(); c != '0' && c != '1' {
			return sfItem{}, false
		}
		p.i++
		return sfItem{}, true
	case c == '@':
		p.i++
		start := p.i
		ok := p.number()
		return sfItem{}, ok && !strings.Contains(p.s[start:p.i], ".")
	case c == '%':
		return sfItem{}, p.displayString()
	default:
		return sfItem{}, false
	}
}

// number accepts an Integer (up to 15 digits) or a Decimal (up to 12 integer
// and 1 to 3 fractional digits).
func (p *sfParser) number() bool {
	if p.peek() == '-' {
		p.i++
	}
	intDigits, fracDigits, decimal := 0, 0, false
scan:
	for !p.eof() {
		c := p.peek()
		switch {
		case isDigit(c) && decimal:
			fracDigits++
		case isDigit(c):
			intDigits++
		case c == '.' && !decimal:
			decimal = true
		default:
			break scan
		}
		p.i++
	}
	if intDigits == 0 {
		return false
	}
	if !decimal {
		return intDigits <= 15
	}
	return intDigits <= 12 && fracDigits >= 1 && fracDigits <= 3
}

func (p *sfParser) str() (sfItem, bool) {
	p.i++
	var b strings.Builder
	for !p.eof() {
		c := p.peek()
		p.i++
		switch {
		case c == '\\':
			if n := p.peek(); n != '"' && n != '\\' {
				return sfItem{}, false
			}
			b.WriteByte(p.peek())
			p.i++
		case c == '"':
			return sfItem{kind: sfString, val: b.String()}, true
		case c < 0x20 || c > 0x7e:
			return sfItem{}, false
		default:
			b.WriteByte(c)
		}
	}
	return sfItem{}, false
}

func (p *sfParser) displayString() bool {
	p.i++
	if p.peek() != '"' {
		return false
	}
	p.i++
	for !p.eof() {
		c := p.peek()
		p.i++
		switch {
		case c == '"':
			return true
		case c == '%':
			if p.i+2 > len(p.s) || !isLCHex(p.s[p.i]) || !isLCHex(p.s[p.i+1]) {
				return false
			}
			p.i += 2
		case c < 0x20 || c > 0x7e:
			return false
		}
	}
	return false
}

func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isLCHex(c byte) bool   { return isDigit(c) || (c >= 'a' && c <= 'f') }
func isTChar(c byte) bool {
	return isAlpha(c) || isDigit(c) || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}
