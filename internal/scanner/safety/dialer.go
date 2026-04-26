package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// PinnedDial is the SSRF-resistant dial helper. host is the canonical
// hostname (used for friendly errors and to detect rebinding); pinned
// is the immutable list of IPs validated at admission; p is the
// re-check policy applied at the syscall level.
//
// PinnedDial accepts an "addr" of the form "host:port" — if host is the
// canonical hostname it is rewritten to the first pinned IP; if host is
// already a literal IP it must be one of the pinned ones.
func PinnedDial(ctx context.Context, network, addr, hostname string, pinned []net.IP, p *Policy) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safety: bad dial address %q: %w", addr, err)
	}

	target := ""
	switch {
	case net.ParseIP(host) != nil:
		// Direct IP literal: must be one of the pinned IPs.
		ip := net.ParseIP(host)
		if !ipInSet(ip, pinned) {
			return nil, fmt.Errorf("safety: dial to non-pinned IP %s (target %s)", ip, hostname)
		}
		target = net.JoinHostPort(host, port)
	case strings.EqualFold(host, hostname):
		if len(pinned) == 0 {
			return nil, errors.New("safety: target has no pinned IPs")
		}
		target = net.JoinHostPort(pinned[0].String(), port)
	default:
		return nil, fmt.Errorf("safety: dial to unexpected host %s (target %s)", host, hostname)
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: makeControlChecker(p, pinned),
	}
	return dialer.DialContext(ctx, network, target)
}

// makeControlChecker returns a net.Dialer.Control hook that re-evaluates
// the IP being dialed at the syscall level (defence in depth: if the
// kernel-level resolution somehow returns something different from what
// we pinned, we still reject).
func makeControlChecker(p *Policy, pinned []net.IP) func(network, address string, c syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("safety/control: bad address %q", address)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("safety/control: address has no IP literal: %s", address)
		}
		if !ipInSet(ip, pinned) {
			return fmt.Errorf("safety/control: dialed IP %s not in pinned set", ip)
		}
		if p != nil {
			if d := p.EvaluateIP(ip); !d.Allowed {
				return fmt.Errorf("safety/control: blocked %s (%s)", ip, d.Reason)
			}
		}
		return nil
	}
}

// HTTPTransport returns an *http.Transport whose DialContext uses
// PinnedDial. Designed to drop into http.Client.Transport.
func HTTPTransport(hostname string, pinned []net.IP, p *Policy) *http.Transport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return PinnedDial(ctx, network, addr, hostname, pinned, p)
	}
	// Keep parity with internal/scanner/headers — we want explicit
	// Content-Encoding rather than transport-level gzip decoding.
	base.DisableCompression = true
	return base
}

// HTTPClient builds an *http.Client wrapped around HTTPTransport. The
// caller still needs to set CheckRedirect and Timeout if they care.
func HTTPClient(hostname string, pinned []net.IP, p *Policy) *http.Client {
	return &http.Client{
		Transport: HTTPTransport(hostname, pinned, p),
		Timeout:   30 * time.Second,
	}
}

func ipInSet(ip net.IP, set []net.IP) bool {
	for _, s := range set {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}
