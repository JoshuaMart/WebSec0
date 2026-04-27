package safety_test

import (
	"context"
	"net"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scanner/safety"
)

// stubResolver lets us test ResolveAndValidate without DNS.
type stubResolver struct{ ips []net.IPAddr }

func (s *stubResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return s.ips, nil
}

func TestEvaluateIP_BlocksMetadata(t *testing.T) {
	t.Parallel()
	p := safety.Default()
	for _, addr := range []string{"169.254.169.254", "fd00:ec2::254"} {
		ip := net.ParseIP(addr)
		if d := p.EvaluateIP(ip); d.Allowed {
			t.Errorf("%s allowed, want blocked", addr)
		}
	}
}

func TestEvaluateIP_BlocksLoopback(t *testing.T) {
	t.Parallel()
	p := safety.Default()
	for _, addr := range []string{"127.0.0.1", "127.5.5.5", "::1", "::ffff:127.0.0.1"} {
		if d := p.EvaluateIP(net.ParseIP(addr)); d.Allowed {
			t.Errorf("%s allowed, want blocked", addr)
		}
	}
}

func TestEvaluateIP_BlocksPrivate(t *testing.T) {
	t.Parallel()
	p := safety.Default()
	for _, addr := range []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1",
		"100.64.0.1",  // CGNAT
		"169.254.5.5", // link-local
		"fc00::1",     // ULA
		"fe80::1",     // link-local v6
	} {
		if d := p.EvaluateIP(net.ParseIP(addr)); d.Allowed {
			t.Errorf("%s allowed, want blocked", addr)
		}
	}
}

func TestEvaluateIP_AllowsPublicAddresses(t *testing.T) {
	t.Parallel()
	p := safety.Default()
	for _, addr := range []string{"1.1.1.1", "8.8.8.8", "203.0.113.10", "2606:4700:4700::1111"} {
		if addr == "203.0.113.10" {
			// In TEST-NET-3 — should be blocked by RefusePrivateRanges.
			continue
		}
		if d := p.EvaluateIP(net.ParseIP(addr)); !d.Allowed {
			t.Errorf("%s blocked (%s), want allowed", addr, d.Reason)
		}
	}
}

func TestPermissiveStillBlocksMetadata(t *testing.T) {
	t.Parallel()
	p := safety.Permissive()
	if d := p.EvaluateIP(net.ParseIP("169.254.169.254")); d.Allowed {
		t.Error("Permissive allowed metadata — must always be blocked")
	}
	// But permissive lets loopback through.
	if d := p.EvaluateIP(net.ParseIP("127.0.0.1")); !d.Allowed {
		t.Errorf("Permissive blocks loopback (%s); should allow", d.Reason)
	}
}

func TestAllowedCIDRBypass(t *testing.T) {
	t.Parallel()
	p := safety.Default()
	if !p.AddAllowedCIDR("10.42.0.0/16") {
		t.Fatal("AddAllowedCIDR rejected valid CIDR")
	}
	// 10.42.0.5 should now pass...
	if d := p.EvaluateIP(net.ParseIP("10.42.0.5")); !d.Allowed {
		t.Errorf("allowed CIDR ignored (%s)", d.Reason)
	}
	// ...but 10.42.0.0/16 doesn't override metadata blocking.
	if d := p.EvaluateIP(net.ParseIP("169.254.169.254")); d.Allowed {
		t.Error("metadata still blockable through allowed_cidrs")
	}
	// And other private ranges still blocked.
	if d := p.EvaluateIP(net.ParseIP("10.0.0.1")); d.Allowed {
		t.Error("non-allowlisted private range allowed")
	}
}

func TestEvaluateHost_DomainBlocklist(t *testing.T) {
	t.Parallel()
	p := safety.Default()
	for _, host := range []string{"agency.gov", "sub.agency.gov", "army.mil"} {
		if d := p.EvaluateHost(host); d.Allowed {
			t.Errorf("%s allowed", host)
		}
	}
}

func TestEvaluateHost_AllowedHostsBypass(t *testing.T) {
	t.Parallel()
	p := safety.Default()
	p.AllowedHosts = []string{"*.staging.corp"}
	if d := p.EvaluateHost("api.staging.corp"); !d.Allowed {
		t.Errorf("wildcard allow failed (%s)", d.Reason)
	}
}

// Simulates a DNS-rebinding response set: one public IP plus one
// loopback. Every IP must be safe — the dialer can't predict which one
// a future resolution returns — so the whole target is rejected.
func TestResolveAndValidate_BlockedOnAnyIP(t *testing.T) {
	t.Parallel()
	r := &stubResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("1.1.1.1")},
		{IP: net.ParseIP("127.0.0.1")},
	}}
	_, decision := safety.ResolveAndValidate(context.Background(), "rebind.example", safety.Default(), r)
	if decision == nil || decision.Reason != safety.ReasonLoopback {
		t.Errorf("decision = %+v, want loopback rejection", decision)
	}
}

func TestResolveAndValidate_AllPublicPasses(t *testing.T) {
	t.Parallel()
	r := &stubResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("1.1.1.1")},
		{IP: net.ParseIP("8.8.8.8")},
	}}
	ips, decision := safety.ResolveAndValidate(context.Background(), "ok.example", safety.Default(), r)
	if decision != nil {
		t.Fatalf("decision = %+v, want allowed", decision)
	}
	if len(ips) != 2 {
		t.Errorf("ips = %v, want 2", ips)
	}
}

func TestPinnedDial_RejectsNonPinnedIP(t *testing.T) {
	t.Parallel()
	pinned := []net.IP{net.ParseIP("203.0.113.10")}
	_, err := safety.PinnedDial(context.Background(), "tcp", "127.0.0.1:80", "evil.example",
		pinned, safety.Default())
	if err == nil {
		t.Error("expected error dialing non-pinned IP")
	}
}

func TestPinnedDial_RejectsUnexpectedHost(t *testing.T) {
	t.Parallel()
	pinned := []net.IP{net.ParseIP("203.0.113.10")}
	_, err := safety.PinnedDial(context.Background(), "tcp", "other.example:80", "expected.example",
		pinned, safety.Default())
	if err == nil {
		t.Error("expected error dialing unexpected host")
	}
}
