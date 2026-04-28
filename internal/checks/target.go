package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"
)

// DefaultUserAgent is used when a Target is constructed without one set.
const DefaultUserAgent = "WebSec0/0.1.0 (+https://websec0.example/about; passive-scan)"

// Target is the input handed to every Check during a scan. It holds the
// canonical hostname, the original input string, and a per-scan DNS cache
// that all checks share to avoid redundant lookups (cf. SPECIFICATIONS.md
// §4.5).
type Target struct {
	// Hostname is the canonical lowercase hostname (no scheme, no port,
	// no path). It is the value scoped by the SSRF/blocklist filters.
	Hostname string
	// Host is Hostname plus an optional `:port` suffix, used when
	// composing URLs (so tests against httptest.NewServer can target
	// 127.0.0.1:NNNN). For real scans Host == Hostname.
	Host string
	// Original is the unmodified user-supplied string (URL or hostname).
	Original string
	// UserAgent is the User-Agent header used by HTTP-based checks.
	// Defaults to DefaultUserAgent when empty.
	UserAgent string
	// HTTPClient is the HTTP client used by HTTP-based checks. nil means
	// http.DefaultClient.
	HTTPClient *http.Client
	// DNSResolverAddr is the host:port of the resolver consulted by
	// internal/scanner/dns. Empty means a sensible package default
	// (Cloudflare 1.1.1.1:53). Tests inject mock servers here.
	DNSResolverAddr string

	// PinnedIPs is the immutable set of IPs the SSRF gatekeeper resolved
	// at admission. All outbound connections from the scanner must use
	// one of these — see internal/scanner/safety. Empty in tests / CLI
	// when running without a Policy.
	PinnedIPs []net.IP

	// resolver is the DNS lookup function. Tests may swap it; nil means
	// net.DefaultResolver.
	resolver Resolver

	dnsMu sync.RWMutex
	dns   map[string][]net.IP

	// Per-target value cache shared between checks (e.g. one HTTP fetch
	// for all six security.txt checks). Backed by singleflight so the
	// factory runs at most once per key under concurrent callers.
	cacheMu sync.RWMutex
	cache   map[string]cacheEntry
	sf      singleflight.Group
}

type cacheEntry struct {
	value any
	err   error
}

// Resolver mirrors the small subset of net.Resolver we depend on. It exists
// so tests can inject a stub without spinning up a real DNS server.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// NewTarget validates the input and returns a Target with an empty DNS
// cache. resolver may be nil to use net.DefaultResolver.
func NewTarget(input string, resolver Resolver) (*Target, error) {
	host, withPort, err := parseHostWithPort(input)
	if err != nil {
		return nil, err
	}
	return &Target{
		Hostname: host,
		Host:     withPort,
		Original: input,
		resolver: resolver,
		dns:      make(map[string][]net.IP),
		cache:    make(map[string]cacheEntry),
	}, nil
}

// UA returns the configured User-Agent (or the package default).
func (t *Target) UA() string {
	if t.UserAgent != "" {
		return t.UserAgent
	}
	return DefaultUserAgent
}

// Client returns the configured *http.Client (or http.DefaultClient).
func (t *Target) Client() *http.Client {
	if t.HTTPClient != nil {
		return t.HTTPClient
	}
	return http.DefaultClient
}

// FirstPinnedIP returns the first IP captured at admission, or nil when
// no policy was applied (tests / standalone CLI without --strict).
func (t *Target) FirstPinnedIP() net.IP {
	if len(t.PinnedIPs) == 0 {
		return nil
	}
	return t.PinnedIPs[0]
}

// DialAddress returns the "host:port" string that outbound TCP dials
// should use. When PinnedIPs is set, the hostname is replaced by the
// pinned IP; otherwise the original hostname is used.
func (t *Target) DialAddress(port string) string {
	if ip := t.FirstPinnedIP(); ip != nil {
		return net.JoinHostPort(ip.String(), port)
	}
	host := t.Host
	if host == "" {
		host = t.Hostname
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

// CacheValue runs factory at most once per key for the lifetime of the
// Target — concurrent callers either join the in-flight call or hit the
// cached result. Safe for use as a per-scan, per-target memo.
func (t *Target) CacheValue(key string, factory func() (any, error)) (any, error) {
	t.cacheMu.RLock()
	if e, ok := t.cache[key]; ok {
		t.cacheMu.RUnlock()
		return e.value, e.err
	}
	t.cacheMu.RUnlock()

	v, err, _ := t.sf.Do(key, func() (any, error) {
		t.cacheMu.RLock()
		if e, ok := t.cache[key]; ok {
			t.cacheMu.RUnlock()
			return e.value, e.err
		}
		t.cacheMu.RUnlock()

		v, err := factory()

		t.cacheMu.Lock()
		t.cache[key] = cacheEntry{value: v, err: err}
		t.cacheMu.Unlock()
		return v, err
	})
	return v, err
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

// parseHostWithPort splits input into a bare hostname and a host:port
// composite. The composite preserves any explicit port the caller wrote
// (httptest URLs, non-standard deployments). For inputs without a port
// the two return values are identical.
func parseHostWithPort(input string) (host string, hostPort string, err error) {
	if strings.ContainsAny(input, "\t\r\n") {
		return "", "", fmt.Errorf("target: input contains control whitespace")
	}
	s := strings.TrimSpace(input)
	if s == "" {
		return "", "", errors.New("target: empty input")
	}
	if strings.Contains(s, " ") {
		return "", "", fmt.Errorf("target: embedded space")
	}
	if strings.Contains(s, "://") {
		u, perr := url.Parse(s)
		if perr != nil {
			return "", "", fmt.Errorf("target: parse URL: %w", perr)
		}
		s = u.Host
	} else if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	s = strings.ToLower(s)
	if s == "" {
		return "", "", errors.New("target: empty hostname")
	}
	host = s
	hostPort = s
	if strings.HasPrefix(s, "[") {
		// IPv6 literal. Keep brackets in hostPort; strip them in host.
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("target: malformed IPv6 literal %q", s)
		}
		host = s[1:end]
	} else if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i+1:], ":") {
		host = s[:i]
	}
	if host == "" {
		return "", "", errors.New("target: empty hostname")
	}
	return host, hostPort, nil
}
