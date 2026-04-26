package checks

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

type stubResolver struct {
	calls atomic.Int32
	ips   []net.IPAddr
}

func (s *stubResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	s.calls.Add(1)
	return s.ips, nil
}

func TestParseHostWithPort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, host, hostPort string
		wantErr            bool
	}{
		{"example.com", "example.com", "example.com", false},
		{"Example.COM", "example.com", "example.com", false},
		{"https://example.com/path", "example.com", "example.com", false},
		{"https://example.com:8443/x", "example.com", "example.com:8443", false},
		{"example.com:8443", "example.com", "example.com:8443", false},
		{"example.com/foo", "example.com", "example.com", false},
		{"127.0.0.1:9090", "127.0.0.1", "127.0.0.1:9090", false},
		{"", "", "", true},
		{"   ", "", "", true},
		{"http://example.com\n", "", "", true},
	}
	for _, c := range cases {
		host, hostPort, err := parseHostWithPort(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseHostWithPort(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if host != c.host || hostPort != c.hostPort {
			t.Errorf("parseHostWithPort(%q) = (%q, %q), want (%q, %q)",
				c.in, host, hostPort, c.host, c.hostPort)
		}
	}
}

func TestResolveCachesPerHost(t *testing.T) {
	t.Parallel()
	r := &stubResolver{ips: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}}
	tgt, err := NewTarget("example.com", r)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	for i := 0; i < 5; i++ {
		ips, err := tgt.Resolve(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.10")) {
			t.Fatalf("ips = %v", ips)
		}
	}
	if r.calls.Load() != 1 {
		t.Errorf("resolver called %d times, want 1 (cache miss)", r.calls.Load())
	}
}
