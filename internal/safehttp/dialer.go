package safehttp

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// PinnedDialer returns a *net.Dialer whose Control callback refuses to
// connect to any address other than target.AddrPort(). It is the second
// layer of the SSRF defence (SPEC §8.2): callers should pass the pinned
// address to DialContext directly, and Control is the belt-and-braces
// check that the address was not silently swapped.
func PinnedDialer(target *Target, timeout time.Duration) *net.Dialer {
	expected := target.AddrPort()
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_ string, address string, _ syscall.RawConn) error {
			return checkPinned(address, expected)
		},
	}
}

func checkPinned(address string, expected netip.AddrPort) error {
	actual, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: malformed dial address %q", ErrIPPinViolation, address)
	}
	if actual.Addr().Is4In6() {
		actual = netip.AddrPortFrom(actual.Addr().Unmap(), actual.Port())
	}
	if actual != expected {
		return fmt.Errorf("%w: dial target %s does not match pinned %s", ErrIPPinViolation, actual, expected)
	}
	return nil
}
