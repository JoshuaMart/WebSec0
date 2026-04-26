// Package safety implements WebSec101's anti-SSRF defences: hostname /
// IP blocklists, DNS-rebinding-resistant resolution (pin-and-recheck),
// and a custom net.Dialer that re-validates every outbound connection
// at the syscall level.
package safety

import (
	"fmt"
	"net"
)

// Reason identifies why a target / IP was rejected.
type Reason string

const (
	ReasonAllowed        Reason = ""
	ReasonCloudMetadata  Reason = "cloud_metadata"
	ReasonLoopback       Reason = "loopback"
	ReasonPrivateRange   Reason = "private_range"
	ReasonCGNAT          Reason = "cgnat"
	ReasonLinkLocal      Reason = "link_local"
	ReasonDomainBlocked  Reason = "domain_blocklist"
	ReasonInvalidTarget  Reason = "invalid_target"
	ReasonResolutionErr  Reason = "resolution_error"
	ReasonUnexpectedHost Reason = "unexpected_host"
)

// Hard-coded CIDR groups. Extending these is a deliberate code change so
// the surface stays auditable.
var (
	// Metadata endpoints — vol d'IAM creds en une requête.
	// AWS / Azure / GCP / OpenStack share 169.254.169.254;
	// AWS IPv6 metadata is fd00:ec2::254.
	metadataCIDRs = mustParseCIDRs(
		"169.254.169.254/32",
		"fd00:ec2::254/128",
	)

	// Loopback — 127.0.0.0/8 and ::1 plus the unspecified zero address.
	loopbackCIDRs = mustParseCIDRs(
		"127.0.0.0/8",
		"::1/128",
		"::/128",
	)

	// CGNAT (RFC 6598) — often forgotten.
	cgnatCIDRs = mustParseCIDRs(
		"100.64.0.0/10",
	)

	// Link-local v4 (incl. metadata range) and v6.
	linkLocalCIDRs = mustParseCIDRs(
		"169.254.0.0/16",
		"fe80::/10",
	)

	// RFC 1918 + ULA + IPv4-mapped + special-purpose blocks.
	privateCIDRs = mustParseCIDRs(
		"0.0.0.0/8",       // current network
		"10.0.0.0/8",      // RFC 1918
		"172.16.0.0/12",   // RFC 1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.168.0.0/16",  // RFC 1918
		"198.18.0.0/15",   // benchmark testing
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved + 255.255.255.255 broadcast
		"fc00::/7",        // ULA (Unique Local). IPv4-mapped (::ffff:0:0/96)
		// is intentionally NOT listed here — Go's net package stores
		// every IPv4 internally as ::ffff:a.b.c.d, so a /96 entry would
		// match every IPv4 address. EvaluateIP canonicalises via To4()
		// before matching so ::ffff:127.0.0.1 already collapses to the
		// IPv4 loopback rule.
		"64:ff9b::/96",  // NAT64
		"100::/64",      // discard prefix
		"2001::/32",     // Teredo
		"2001:db8::/32", // documentation
	)
)

// mustParseCIDRs panics on bad input — used only for the hard-coded
// constants, where a typo is a build-time bug.
func mustParseCIDRs(in ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(in))
	for _, s := range in {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Sprintf("safety: bad hard-coded CIDR %q: %v", s, err))
		}
		out = append(out, n)
	}
	return out
}

// matchesAny reports whether ip is inside any cidr in the list.
func matchesAny(ip net.IP, cidrs []*net.IPNet) bool {
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
