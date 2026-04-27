package safety

import (
	"net"
	"strings"
)

// Policy is the runtime configuration of the SSRF / domain-blocklist
// gatekeeper. Each toggle is independent and additive (allowed_*
// bypasses everything except cloud-metadata).
type Policy struct {
	RefusePrivateRanges bool
	RefuseLoopback      bool
	RefuseCGNAT         bool
	// RefuseLinkLocal — covers everything in 169.254.0.0/16 and fe80::/10
	// other than the metadata IPs (those are governed by RefuseMetadata).
	RefuseLinkLocal bool
	// RefuseMetadata is the one toggle we never want to disable on a
	// cloud deployment: a single request to 169.254.169.254 → IAM theft.
	// Default true; the server logs WARN on startup if false.
	RefuseMetadata bool

	DomainBlocklist []string

	AllowedCIDRs []*net.IPNet
	AllowedHosts []string // exact hostname or `*.suffix`
}

// Default returns the strict baseline matching SPECIFICATIONS.md §4.6.
func Default() *Policy {
	return &Policy{
		RefusePrivateRanges: true,
		RefuseLoopback:      true,
		RefuseCGNAT:         true,
		RefuseLinkLocal:     true,
		RefuseMetadata:      true,
		DomainBlocklist:     []string{".gov", ".mil", ".gouv.fr", ".gc.ca"},
	}
}

// Permissive disables every IP-level restriction except metadata. Used
// by `websec0-cli scan --unsafe` and self-hosted lab deployments.
func Permissive() *Policy {
	return &Policy{
		RefuseMetadata: true,
	}
}

// AddAllowedCIDR appends a CIDR to the allowlist (returns false on
// parse error so callers can surface the bad input).
func (p *Policy) AddAllowedCIDR(s string) bool {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	p.AllowedCIDRs = append(p.AllowedCIDRs, n)
	return true
}

// Decision is the verdict returned by the policy evaluator.
type Decision struct {
	Allowed bool
	Reason  Reason
	IP      net.IP
	Host    string
	// Configurable signals whether the rejection can be lifted by
	// changing config.yaml. Always false for cloud_metadata, malformed
	// inputs, and resolution errors.
	Configurable bool
}

// EvaluateIP scores a single resolved IP. Allowed CIDRs override
// loopback/private/cgnat/link-local but NOT metadata.
func (p *Policy) EvaluateIP(ip net.IP) Decision {
	if ip == nil {
		return Decision{Reason: ReasonInvalidTarget, IP: ip}
	}
	// Canonicalise IPv4-mapped form to 4-byte IPv4 so the IPv4 rules
	// catch `::ffff:127.0.0.1` and friends (cf. blocklist.go comment).
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// 1. Cloud-metadata always wins (when enabled). Hard "no" before any
	//    allowlist gets the chance to override — protects the case where
	//    the user's allowed_cidrs accidentally includes 169.254.0.0/16.
	if p.RefuseMetadata && matchesAny(ip, metadataCIDRs) {
		return Decision{Reason: ReasonCloudMetadata, IP: ip, Configurable: false}
	}

	// 2. Explicit allowlist.
	for _, cidr := range p.AllowedCIDRs {
		if cidr.Contains(ip) {
			return Decision{Allowed: true, IP: ip}
		}
	}

	// 3. Negative rules.
	if p.RefuseLoopback && matchesAny(ip, loopbackCIDRs) {
		return Decision{Reason: ReasonLoopback, IP: ip, Configurable: true}
	}
	if p.RefuseCGNAT && matchesAny(ip, cgnatCIDRs) {
		return Decision{Reason: ReasonCGNAT, IP: ip, Configurable: true}
	}
	if p.RefuseLinkLocal && matchesAny(ip, linkLocalCIDRs) {
		return Decision{Reason: ReasonLinkLocal, IP: ip, Configurable: true}
	}
	if p.RefusePrivateRanges && matchesAny(ip, privateCIDRs) {
		return Decision{Reason: ReasonPrivateRange, IP: ip, Configurable: true}
	}

	return Decision{Allowed: true, IP: ip}
}

// EvaluateHost runs the domain-level checks (allowed hosts +
// blocklisted suffixes). It deliberately does NOT do DNS — that
// happens once, in ResolveAndValidate.
func (p *Policy) EvaluateHost(host string) Decision {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return Decision{Reason: ReasonInvalidTarget, Configurable: false}
	}

	for _, allowed := range p.AllowedHosts {
		if matchHost(host, strings.ToLower(allowed)) {
			return Decision{Allowed: true, Host: host}
		}
	}

	for _, suffix := range p.DomainBlocklist {
		s := strings.ToLower(suffix)
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		if strings.HasSuffix(host, s) || host == strings.TrimPrefix(s, ".") {
			return Decision{Reason: ReasonDomainBlocked, Host: host, Configurable: true}
		}
	}
	return Decision{Allowed: true, Host: host}
}

// matchHost matches host against a pattern; pattern may be exact or
// `*.suffix.example`.
func matchHost(host, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".suffix.example"
		return strings.HasSuffix(host, suffix) || host == suffix[1:]
	}
	return host == pattern
}
