package safety

import (
	"errors"
	"net"
)

// ConfigInput mirrors the SecurityConfig fields the safety package
// needs. Defined separately so we don't import internal/config (avoids
// pulling koanf into every test that uses Policy).
type ConfigInput struct {
	RefusePrivateRanges bool
	RefuseLoopback      bool
	RefuseCGNAT         bool
	RefuseLinkLocal     bool
	RefuseMetadata      bool
	DomainBlocklist     []string
	AllowedCIDRs        []string
	AllowedHosts        []string
}

// FromConfig builds a Policy from a ConfigInput. Bad CIDRs in
// AllowedCIDRs cause an error; the rest is permissive.
func FromConfig(c ConfigInput) (*Policy, error) {
	p := &Policy{
		RefusePrivateRanges: c.RefusePrivateRanges,
		RefuseLoopback:      c.RefuseLoopback,
		RefuseCGNAT:         c.RefuseCGNAT,
		RefuseLinkLocal:     c.RefuseLinkLocal,
		RefuseMetadata:      c.RefuseMetadata,
		DomainBlocklist:     append([]string(nil), c.DomainBlocklist...),
		AllowedHosts:        append([]string(nil), c.AllowedHosts...),
	}
	for _, raw := range c.AllowedCIDRs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, errors.New("safety: invalid allowed_cidr " + raw)
		}
		p.AllowedCIDRs = append(p.AllowedCIDRs, n)
	}
	return p, nil
}
