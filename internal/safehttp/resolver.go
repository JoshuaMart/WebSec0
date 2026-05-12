package safehttp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// LookupFunc resolves a host to a list of IP addresses. The default
// implementation delegates to net.DefaultResolver.LookupNetIP, but tests
// (and future caching layers) can inject a custom function.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// DefaultLookup uses the Go default resolver.
func DefaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Target is the resolved, validated, IP-pinned destination of a scan.
// Construction goes exclusively through Resolver.Resolve.
type Target struct {
	Scheme   string
	Host     string // FQDN, lowercase, ASCII
	Port     int
	IP       netip.Addr
	addrPort netip.AddrPort
}

// Address returns the IP:port string the dialer must connect to.
func (t *Target) Address() string { return t.addrPort.String() }

// AddrPort returns the pinned IP+port as a netip.AddrPort.
func (t *Target) AddrPort() netip.AddrPort { return t.addrPort }

// HostPort returns the canonical "host:port" used for SNI and the Host
// header. When Port is the scheme default (443 for https), the port is
// omitted to keep the form RFC-friendly.
func (t *Target) HostPort() string {
	if t.Port == 443 {
		return t.Host
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// URL builds a fully-qualified URL for the given absolute path.
func (t *Target) URL(path string) string {
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	return t.Scheme + "://" + t.HostPort() + path
}

// Resolver owns the single-lookup contract: it picks the first IP returned
// by the resolver that satisfies the policy, and locks the result for the
// rest of the scan.
type Resolver struct {
	Lookup LookupFunc // nil → DefaultLookup
	Policy Policy
}

// Resolve performs one DNS lookup and returns a Target pinned to the first
// allowed IP. Errors are typed:
//
//   - ErrNoAllowedIP when DNS returned zero addresses.
//   - ErrPrivateTargetBlocked when every returned address is policy-blocked.
func (r *Resolver) Resolve(ctx context.Context, v *Validated) (*Target, error) {
	lookup := r.Lookup
	if lookup == nil {
		lookup = DefaultLookup
	}
	ips, err := lookup(ctx, v.Host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", v.Host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoAllowedIP, v.Host)
	}
	for _, ip := range ips {
		if ip.Is4In6() {
			ip = ip.Unmap()
		}
		if r.Policy.IsBlocked(ip) {
			continue
		}
		return &Target{
			Scheme:   v.Scheme,
			Host:     v.Host,
			Port:     v.Port,
			IP:       ip,
			addrPort: netip.AddrPortFrom(ip, uint16(v.Port)), //nolint:gosec // v.Port is range-checked in ValidateInput
		}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrPrivateTargetBlocked, v.Host)
}
