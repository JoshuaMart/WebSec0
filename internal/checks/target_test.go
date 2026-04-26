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

func TestParseHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"example.com", "example.com", false},
		{"Example.COM", "example.com", false},
		{"https://example.com/path", "example.com", false},
		{"https://example.com:8443/x", "example.com", false},
		{"example.com:8443", "example.com", false},
		{"example.com/foo", "example.com", false},
		{"", "", true},
		{"   ", "", true},
		{"http://example.com\n", "", true},
	}
	for _, c := range cases {
		got, err := parseHost(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseHost(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("parseHost(%q) = %q, want %q", c.in, got, c.want)
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
