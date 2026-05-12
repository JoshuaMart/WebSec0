// Package safehttp is the security-critical core that gates every outbound
// connection made by a scan. It validates user input, resolves DNS once,
// pins the destination IP for the lifetime of the scan, refuses off-host
// redirects, caps response bodies and rate-limits both clients and targets.
// See SPECIFICATIONS.md §8.
package safehttp

import "errors"

// Sentinel errors. All are matchable via errors.Is.
var (
	// ErrInvalidScheme — the input scheme is not in the allow-list.
	ErrInvalidScheme = errors.New("safehttp: invalid scheme")
	// ErrInvalidHost — the hostname could not be parsed, is empty, or is
	// not a valid FQDN.
	ErrInvalidHost = errors.New("safehttp: invalid host")
	// ErrIPLiteral — the user supplied a bare IP; only hostnames are accepted.
	ErrIPLiteral = errors.New("safehttp: ip literal not accepted")
	// ErrUserInfo — the URL contains a userinfo component.
	ErrUserInfo = errors.New("safehttp: userinfo not accepted")
	// ErrCustomPortBlocked — a non-default port was requested while
	// allow_custom_ports is false.
	ErrCustomPortBlocked = errors.New("safehttp: custom port blocked")
	// ErrPrivateTargetBlocked — every resolved IP is in a blocked range.
	ErrPrivateTargetBlocked = errors.New("safehttp: private or reserved target blocked")
	// ErrNoAllowedIP — DNS returned no addresses for the host.
	ErrNoAllowedIP = errors.New("safehttp: no resolvable address for target")
	// ErrIPPinViolation — a Dial was attempted against an address other
	// than the pinned target IP.
	ErrIPPinViolation = errors.New("safehttp: ip-pin violation")
	// ErrOffHostRedirect — a redirect pointed away from the original host.
	ErrOffHostRedirect = errors.New("safehttp: off-host redirect refused")
	// ErrTooManyRedirects — redirect chain exceeded the configured limit.
	ErrTooManyRedirects = errors.New("safehttp: too many redirects")
	// ErrBodyTooLarge — the response body exceeded the configured cap.
	ErrBodyTooLarge = errors.New("safehttp: response body exceeds cap")
)
