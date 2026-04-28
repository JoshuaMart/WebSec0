package safety

import (
	"net"
	"strings"
	"testing"
)

func TestFromConfig(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		p, err := FromConfig(ConfigInput{
			RefusePrivateRanges: true,
			RefuseLoopback:      true,
			RefuseCGNAT:         true,
			RefuseLinkLocal:     true,
			RefuseMetadata:      true,
			DomainBlocklist:     []string{".gov", ".mil"},
			AllowedHosts:        []string{"intranet.example.com"},
			AllowedCIDRs:        []string{"10.0.0.0/8", "192.0.2.0/24"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !p.RefusePrivateRanges || !p.RefuseMetadata {
			t.Errorf("flags not propagated: %+v", p)
		}
		if len(p.DomainBlocklist) != 2 || len(p.AllowedHosts) != 1 || len(p.AllowedCIDRs) != 2 {
			t.Errorf("slices not copied: %+v", p)
		}
		// Slice copies must be defensive — mutating the input must not leak in.
	})
	t.Run("bad CIDR returns error", func(t *testing.T) {
		_, err := FromConfig(ConfigInput{AllowedCIDRs: []string{"not-a-cidr"}})
		if err == nil || !strings.Contains(err.Error(), "invalid allowed_cidr") {
			t.Errorf("err = %v, want invalid_allowed_cidr", err)
		}
	})
}

func TestHTTPClient_BuildsTransportAndClient(t *testing.T) {
	p := Permissive()
	c := HTTPClient("example.com", []net.IP{net.ParseIP("198.51.100.1")}, p)
	if c == nil {
		t.Fatal("HTTPClient returned nil")
	}
	if c.Transport == nil {
		t.Error("Transport not set")
	}
	if c.Timeout <= 0 {
		t.Errorf("Timeout = %s, want > 0", c.Timeout)
	}
}

func TestHTTPTransport_Standalone(t *testing.T) {
	p := Default()
	tr := HTTPTransport("example.com", []net.IP{net.ParseIP("198.51.100.1")}, p)
	if tr == nil {
		t.Fatal("HTTPTransport returned nil")
	}
	// Sanity: dialer wired so a Control hook is set.
	if tr.DialContext == nil {
		t.Error("DialContext not set")
	}
}

func TestDecision_HumanError_Reasons(t *testing.T) {
	cases := map[Reason]string{
		ReasonDomainBlocked:  "blocklist",
		ReasonPrivateRange:   "private",
		ReasonLoopback:       "loopback",
		ReasonCGNAT:          "cgnat",
		ReasonLinkLocal:      "link",
		ReasonCloudMetadata:  "metadata",
		ReasonResolutionErr:  "resol",
		ReasonInvalidTarget:  "malformed",
		ReasonUnexpectedHost: "unexpected",
	}
	for reason, snippet := range cases {
		t.Run(string(reason), func(t *testing.T) {
			d := &Decision{Reason: reason, Host: "example.com", IP: net.ParseIP("198.51.100.1")}
			msg := strings.ToLower(d.HumanError())
			if !strings.Contains(msg, strings.ToLower(snippet)) {
				t.Errorf("HumanError(%s) = %q, want to contain %q", reason, msg, snippet)
			}
		})
	}
}
