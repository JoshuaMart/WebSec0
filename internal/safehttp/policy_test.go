package safehttp

import (
	"net/netip"
	"testing"
)

func TestPolicy_AlwaysBlocked(t *testing.T) {
	cases := []string{
		// loopback
		"127.0.0.1", "127.255.255.254", "::1",
		// link-local
		"169.254.169.254", "fe80::1",
		// multicast
		"224.0.0.1", "ff02::1",
		// unspecified
		"0.0.0.0", "::",
	}
	p := Policy{AllowPrivate: true} // even with AllowPrivate, these stay blocked.
	for _, raw := range cases {
		ip := netip.MustParseAddr(raw)
		if !p.IsBlocked(ip) {
			t.Errorf("%s: expected always-blocked, got allowed", raw)
		}
	}
}

func TestPolicy_BlockedWhenPrivateDisallowed(t *testing.T) {
	cases := []string{
		// RFC1918
		"10.0.0.1", "172.16.0.1", "192.168.1.1",
		// CGNAT
		"100.64.0.1",
		// IETF test nets
		"192.0.2.1", "198.51.100.1", "203.0.113.1",
		// benchmark
		"198.18.0.1",
		// reserved future
		"240.0.0.1",
		// IPv6 ULA + doc + NAT64
		"fc00::1", "2001:db8::1", "64:ff9b::1.2.3.4",
	}
	p := Policy{}
	for _, raw := range cases {
		ip := netip.MustParseAddr(raw)
		if !p.IsBlocked(ip) {
			t.Errorf("%s: expected blocked, got allowed", raw)
		}
	}
}

func TestPolicy_AllowPrivateLetsRFC1918Through(t *testing.T) {
	p := Policy{AllowPrivate: true}
	for _, raw := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "fc00::1"} {
		ip := netip.MustParseAddr(raw)
		if p.IsBlocked(ip) {
			t.Errorf("%s: expected allowed with AllowPrivate, got blocked", raw)
		}
	}
}

func TestPolicy_PublicIPsAllowed(t *testing.T) {
	p := Policy{}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		ip := netip.MustParseAddr(raw)
		if p.IsBlocked(ip) {
			t.Errorf("%s: public IP should not be blocked", raw)
		}
	}
}

func TestPolicy_ExtraAlwaysBlocks(t *testing.T) {
	extra := []netip.Prefix{netip.MustParsePrefix("203.0.114.0/24")}
	// AllowPrivate=true must not override the operator list.
	p := Policy{AllowPrivate: true, Extra: extra}
	ip := netip.MustParseAddr("203.0.114.42")
	if !p.IsBlocked(ip) {
		t.Errorf("operator-supplied Extra prefix should always block %s", ip)
	}
	// Outside the extra prefix — public IP allowed.
	if p.IsBlocked(netip.MustParseAddr("8.8.8.8")) {
		t.Errorf("public IP outside Extra should be allowed")
	}
}

func TestPolicy_IPv4MappedIPv6Unwrap(t *testing.T) {
	// ::ffff:10.0.0.1 must be treated as 10.0.0.1 (private).
	p := Policy{}
	ip := netip.MustParseAddr("::ffff:10.0.0.1")
	if !p.IsBlocked(ip) {
		t.Errorf("IPv4-mapped IPv6 of private IPv4 should be blocked")
	}
}
