package safehttp

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func stubLookup(ips ...string) LookupFunc {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return addrs, nil
	}
}

func TestResolver_PicksFirstAllowed(t *testing.T) {
	r := &Resolver{Lookup: stubLookup("10.0.0.1", "8.8.8.8", "1.1.1.1")}
	tgt, err := r.Resolve(context.Background(), &Validated{Scheme: "https", Host: "x.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.IP != netip.MustParseAddr("8.8.8.8") {
		t.Errorf("got pinned IP %s, want 8.8.8.8 (first non-private)", tgt.IP)
	}
}

func TestResolver_AllBlockedReturnsTypedError(t *testing.T) {
	r := &Resolver{Lookup: stubLookup("10.0.0.1", "192.168.1.1", "fc00::1")}
	_, err := r.Resolve(context.Background(), &Validated{Scheme: "https", Host: "x.test", Port: 443})
	if !errors.Is(err, ErrPrivateTargetBlocked) {
		t.Errorf("expected ErrPrivateTargetBlocked, got %v", err)
	}
}

func TestResolver_EmptyLookupReturnsTypedError(t *testing.T) {
	r := &Resolver{Lookup: stubLookup()}
	_, err := r.Resolve(context.Background(), &Validated{Scheme: "https", Host: "x.test", Port: 443})
	if !errors.Is(err, ErrNoAllowedIP) {
		t.Errorf("expected ErrNoAllowedIP, got %v", err)
	}
}

func TestResolver_AllowPrivatePassesThrough(t *testing.T) {
	r := &Resolver{
		Lookup: stubLookup("10.0.0.42"),
		Policy: Policy{AllowPrivate: true},
	}
	tgt, err := r.Resolve(context.Background(), &Validated{Scheme: "https", Host: "internal.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.IP != netip.MustParseAddr("10.0.0.42") {
		t.Errorf("got pinned IP %s, want 10.0.0.42", tgt.IP)
	}
}

func TestResolver_UnwrapsIPv4Mapped(t *testing.T) {
	// ::ffff:8.8.8.8 must be unwrapped before policy check (so it stays
	// public) and stored as the v4 form for canonicalisation.
	r := &Resolver{Lookup: stubLookup("::ffff:8.8.8.8")}
	tgt, err := r.Resolve(context.Background(), &Validated{Scheme: "https", Host: "x.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.IP != netip.MustParseAddr("8.8.8.8") {
		t.Errorf("got %s, want 8.8.8.8 (unwrapped)", tgt.IP)
	}
}

func TestTarget_AddressAndURL(t *testing.T) {
	tgt := &Target{
		Scheme:   "https",
		Host:     "example.com",
		Port:     8443,
		IP:       netip.MustParseAddr("203.0.113.10"),
		addrPort: netip.MustParseAddrPort("203.0.113.10:8443"),
	}
	if tgt.Address() != "203.0.113.10:8443" {
		t.Errorf("Address: %s", tgt.Address())
	}
	if tgt.URL("/foo") != "https://example.com:8443/foo" {
		t.Errorf("URL: %s", tgt.URL("/foo"))
	}
	if tgt.URL("") != "https://example.com:8443/" {
		t.Errorf("URL empty: %s", tgt.URL(""))
	}
	tgt443 := *tgt
	tgt443.Port = 443
	if tgt443.URL("/x") != "https://example.com/x" {
		t.Errorf("URL on :443: %s", tgt443.URL("/x"))
	}
}
