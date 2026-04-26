package safety

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Resolver is the minimal subset of net.Resolver we need; tests inject
// a stub.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ResolveAndValidate evaluates host against the domain-level policy,
// resolves it once, and verifies every returned IP. On success it
// returns the pinned set of IPs that all subsequent dials must use.
//
// This is the centerpiece of the anti-DNS-rebinding strategy: the IPs
// captured here are frozen on the Target, and the safety dialer
// refuses to dial anything outside this set.
func ResolveAndValidate(ctx context.Context, host string, p *Policy, r Resolver) ([]net.IP, *Decision) {
	if p == nil {
		p = Default()
	}
	if d := p.EvaluateHost(host); !d.Allowed {
		return nil, &d
	}

	if r == nil {
		r = net.DefaultResolver
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := r.LookupIPAddr(rctx, host)
	if err != nil {
		return nil, &Decision{
			Reason:       ReasonResolutionErr,
			Host:         host,
			Configurable: false,
		}
	}
	if len(addrs) == 0 {
		return nil, &Decision{
			Reason:       ReasonInvalidTarget,
			Host:         host,
			Configurable: false,
		}
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if d := p.EvaluateIP(a.IP); !d.Allowed {
			d.Host = host
			return nil, &d
		}
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// HumanError renders a Decision as the message returned to API clients.
func (d *Decision) HumanError() string {
	switch d.Reason { //nolint:exhaustive // ReasonAllowed never reaches HumanError
	case ReasonCloudMetadata:
		return fmt.Sprintf("target resolves to a cloud metadata endpoint (%s)", d.IP)
	case ReasonLoopback:
		return fmt.Sprintf("target resolves to a loopback address (%s)", d.IP)
	case ReasonPrivateRange:
		return fmt.Sprintf("target resolves to a private RFC 1918/ULA range (%s)", d.IP)
	case ReasonCGNAT:
		return fmt.Sprintf("target resolves to the CGNAT range (%s)", d.IP)
	case ReasonLinkLocal:
		return fmt.Sprintf("target resolves to a link-local address (%s)", d.IP)
	case ReasonDomainBlocked:
		return fmt.Sprintf("target hostname is on the domain blocklist (%s)", d.Host)
	case ReasonResolutionErr:
		return fmt.Sprintf("target hostname does not resolve (%s)", d.Host)
	case ReasonInvalidTarget:
		return "target is empty or malformed"
	case ReasonUnexpectedHost:
		return fmt.Sprintf("connection to unexpected host %s", d.Host)
	}
	return "target rejected"
}
