package safehttp

import "net/netip"

// extraBlockedRanges catches the ranges the stdlib helpers do not flag as
// "private". Operators can extend this via Policy.Extra. See SPEC §8.3.
var extraBlockedRanges = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmark
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved future-use
	// IPv6
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64 well-known
	netip.MustParsePrefix("100::/64"),      // discard prefix
}

// Policy is the runtime decision table for accepting or rejecting a target IP.
type Policy struct {
	// AllowPrivate, when true, lifts the block on RFC1918 + extra reserved
	// ranges. Loopback, link-local, multicast and unspecified remain blocked
	// because connecting to them never makes sense for a remote scanner.
	AllowPrivate bool

	// Extra is the operator-supplied prefix list. These are always blocked,
	// even when AllowPrivate is true — they express "things I never want
	// to scan from this instance".
	Extra []netip.Prefix
}

// IsBlocked reports whether ip must be refused under this policy.
// IPv4-mapped IPv6 addresses are unwrapped before evaluation.
func (p Policy) IsBlocked(ip netip.Addr) bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	// Always-blocked categories.
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	// Operator-supplied list always applies.
	for _, prefix := range p.Extra {
		if prefix.Contains(ip) {
			return true
		}
	}
	if p.AllowPrivate {
		return false
	}
	if ip.IsPrivate() {
		return true
	}
	for _, prefix := range extraBlockedRanges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
