package safehttp

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func makeTarget(t *testing.T, ipPort string) *Target {
	t.Helper()
	ap := netip.MustParseAddrPort(ipPort)
	return &Target{
		Scheme:   "https",
		Host:     "example.com",
		Port:     int(ap.Port()),
		IP:       ap.Addr(),
		addrPort: ap,
	}
}

func TestPinnedDialer_AcceptsExactMatch(t *testing.T) {
	tgt := makeTarget(t, "203.0.113.42:443")
	d := PinnedDialer(tgt, time.Second)
	if err := d.Control("tcp", "203.0.113.42:443", nil); err != nil {
		t.Errorf("expected nil for matching address, got %v", err)
	}
}

func TestPinnedDialer_RefusesMismatch(t *testing.T) {
	tgt := makeTarget(t, "203.0.113.42:443")
	d := PinnedDialer(tgt, time.Second)
	for _, addr := range []string{
		"8.8.8.8:443",       // different IP
		"203.0.113.42:80",   // different port
		"203.0.113.43:443",  // off-by-one IP
		"[2001:db8::1]:443", // different family
	} {
		err := d.Control("tcp", addr, nil)
		if !errors.Is(err, ErrIPPinViolation) {
			t.Errorf("%s: expected ErrIPPinViolation, got %v", addr, err)
		}
	}
}

func TestPinnedDialer_RefusesMalformed(t *testing.T) {
	tgt := makeTarget(t, "203.0.113.42:443")
	d := PinnedDialer(tgt, time.Second)
	if err := d.Control("tcp", "not-an-ip", nil); !errors.Is(err, ErrIPPinViolation) {
		t.Errorf("expected ErrIPPinViolation for malformed addr, got %v", err)
	}
}

func TestPinnedDialer_UnwrapsIPv4Mapped(t *testing.T) {
	tgt := makeTarget(t, "203.0.113.42:443")
	d := PinnedDialer(tgt, time.Second)
	// The OS may hand us the v4-in-v6 form; the control callback must accept it.
	if err := d.Control("tcp", "[::ffff:203.0.113.42]:443", nil); err != nil {
		t.Errorf("expected nil for v4-mapped v6 of pinned IP, got %v", err)
	}
}
