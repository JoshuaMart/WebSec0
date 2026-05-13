package safehttp

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Validated is the canonical, accepted form of a user-supplied target.
type Validated struct {
	Scheme string
	Host   string // lowercase ASCII FQDN
	Port   int
}

// InputPolicy captures the runtime knobs applied during validation.
type InputPolicy struct {
	AllowedSchemes   []string
	AllowCustomPorts bool
	DefaultPort      int // typically 443
}

// ValidateInput parses raw, applies, and returns the canonical
// components — or a typed error from this package.
func ValidateInput(raw string, p InputPolicy) (*Validated, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrInvalidHost
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHost, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if !slices.Contains(p.AllowedSchemes, scheme) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidScheme, u.Scheme)
	}

	if u.User != nil {
		return nil, ErrUserInfo
	}

	host := u.Hostname()
	if host == "" {
		return nil, ErrInvalidHost
	}
	if isIPLiteral(host) {
		return nil, fmt.Errorf("%w: %q", ErrIPLiteral, host)
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !isValidFQDN(host) {
		return nil, fmt.Errorf("%w: %q is not a valid FQDN", ErrInvalidHost, host)
	}

	port := p.DefaultPort
	if port == 0 {
		port = 443
	}
	if raw := u.Port(); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 65535 {
			return nil, fmt.Errorf("%w: invalid port %q", ErrInvalidHost, raw)
		}
		port = parsed
	}
	if port != 443 && !p.AllowCustomPorts {
		return nil, fmt.Errorf("%w: port %d", ErrCustomPortBlocked, port)
	}

	return &Validated{Scheme: scheme, Host: host, Port: port}, nil
}

func isIPLiteral(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return false
}

// isValidFQDN applies pragmatic RFC 1035 / 1123 rules: ASCII only, 1-253
// chars total, at least one dot (no bare TLD), each label 1-63 chars,
// labels start/end with [a-z0-9] and may contain hyphens internally.
// IDN inputs must be pre-encoded to Punycode (xn--...) by the caller.
func isValidFQDN(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z',
				r >= '0' && r <= '9':
				// ok
			case r == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}
