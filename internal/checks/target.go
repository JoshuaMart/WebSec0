package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

// Target is the input handed to every Check during a scan. It holds the
// canonical hostname, the original input string, and a per-scan DNS cache
// that all checks share to avoid redundant lookups (cf. SPECIFICATIONS.md
// §4.5).
type Target struct {
	// Hostname is the canonical lowercase hostname (no scheme, no port,
	// no path). It is the value scoped by the SSRF/blocklist filters.
	Hostname string
	// Original is the unmodified user-supplied string (URL or hostname).
	Original string

	// resolver is the DNS lookup function. Tests may swap it; nil means
	// net.DefaultResolver.
	resolver Resolver

	dnsMu sync.RWMutex
	dns   map[string][]net.IP
}

// Resolver mirrors the small subset of net.Resolver we depend on. It exists
// so tests can inject a stub without spinning up a real DNS server.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// NewTarget validates the input and returns a Target with an empty DNS
// cache. resolver may be nil to use net.DefaultResolver.
func NewTarget(input string, resolver Resolver) (*Target, error) {
	host, err := parseHost(input)
	if err != nil {
		return nil, err
	}
	return &Target{
		Hostname: host,
		Original: input,
		resolver: resolver,
		dns:      make(map[string][]net.IP),
	}, nil
}

// Resolve returns the IP addresses for host, caching the answer for the
// lifetime of the Target. Subsequent calls for the same host hit the cache.
func (t *Target) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.ToLower(host)

	t.dnsMu.RLock()
	if ips, ok := t.dns[host]; ok {
		t.dnsMu.RUnlock()
		return ips, nil
	}
	t.dnsMu.RUnlock()

	r := t.resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}

	t.dnsMu.Lock()
	t.dns[host] = ips
	t.dnsMu.Unlock()
	return ips, nil
}

// parseHost normalises the input to a bare hostname.
func parseHost(input string) (string, error) {
	if strings.ContainsAny(input, "\t\r\n") {
		return "", fmt.Errorf("target: input contains control whitespace")
	}
	s := strings.TrimSpace(input)
	if s == "" {
		return "", errors.New("target: empty input")
	}
	if strings.Contains(s, " ") {
		return "", fmt.Errorf("target: embedded space")
	}
	// Accept both bare hostnames and full URLs.
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("target: parse URL: %w", err)
		}
		s = u.Hostname()
	} else if strings.Contains(s, "/") {
		s = s[:strings.Index(s, "/")]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i+1:], ":") {
		// Strip trailing :port; keep IPv6 brackets intact.
		if !strings.HasPrefix(s, "[") {
			s = s[:i]
		}
	}
	s = strings.ToLower(s)
	if s == "" {
		return "", errors.New("target: empty hostname")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("target: invalid hostname %q", s)
	}
	return s, nil
}
