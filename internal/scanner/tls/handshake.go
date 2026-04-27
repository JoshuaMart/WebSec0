// Package tls implements the TLS family of WebSec101 checks: modern
// handshake (TLS 1.2 and 1.3 via crypto/tls), certificate validation,
// HSTS, and the HTTP→HTTPS redirect probe.
//
// Legacy TLS (1.0/1.1, raw SSLv2/SSLv3 probes), Heartbleed, and
// Certificate Transparency are scoped to a follow-up phase that brings
// in zcrypto and zgrab2.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/safety"
)

const (
	cacheKey       = "tls.handshake"
	defaultPort    = "443"
	dialTimeout    = 5 * time.Second
	httpFetchTotal = 7 * time.Second
)

// VersionProbe records the outcome of one handshake at a specific TLS
// protocol version.
type VersionProbe struct {
	Version       uint16
	Supported     bool
	NegotiatedCS  uint16
	ALPN          string
	OCSPStapled   bool
	HandshakeErr  error
	PeerCertCount int
	// SCTs holds raw Signed Certificate Timestamps delivered via the TLS
	// handshake extension (RFC 6962 §3.3.1). Non-nil only when Supported=true.
	SCTs [][]byte
}

// HandshakeResult is the per-Target snapshot consumed by every TLS check.
type HandshakeResult struct {
	HostPort string
	Probes   map[uint16]*VersionProbe // keyed by tls.Version*

	// Leaf and Chain are populated from the highest TLS version that
	// completed a handshake. InsecureSkipVerify is used during the probe
	// so we can also evaluate broken servers.
	Leaf  *x509.Certificate
	Chain []*x509.Certificate

	// SystemVerifyErr is non-nil when the chain failed to validate against
	// the system trust store (powers TLS-CERT-CHAIN-INCOMPLETE / SELF-SIGNED).
	SystemVerifyErr error

	// HTTPSReachable mirrors AnySucceeded for ergonomics.
	HTTPSReachable bool
	AnySucceeded   bool

	// HSTSHeader is the raw `Strict-Transport-Security` value from a
	// follow-up HTTPS GET / (empty when none was set or the GET failed).
	HSTSHeader string
	HSTSStatus int
	HSTSErr    error

	// HTTPRedirect captures a single GET against http://host/ to detect
	// the HTTP→HTTPS redirect (TLS-REDIRECT-HTTP-TO-HTTPS).
	HTTPProbe *HTTPProbe
}

// HTTPProbe records the result of a single non-following GET against the
// target's plain-HTTP root.
type HTTPProbe struct {
	StatusCode  int
	Location    string
	IsHTTPS     bool
	RedirectErr error
}

// versionsToProbe lists the modern protocol versions we attempt. Order
// matters: TLS 1.3 first so a successful handshake provides the leaf
// certificate without needing 1.2.
var versionsToProbe = []uint16{tls.VersionTLS13, tls.VersionTLS12}

// Fetch performs (or memoises) the per-Target TLS+HSTS+redirect probe.
// All TLS checks call this and consume its HandshakeResult.
func Fetch(ctx context.Context, t *checks.Target) (*HandshakeResult, error) {
	v, err := t.CacheValue(cacheKey, func() (any, error) {
		return doFetch(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	res, _ := v.(*HandshakeResult)
	if res == nil {
		return nil, errors.New("tls: nil cached result")
	}
	return res, nil
}

func hostPort(t *checks.Target) string {
	h := t.Host
	if h == "" {
		h = t.Hostname
	}
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h
	}
	return net.JoinHostPort(h, defaultPort)
}

func doFetch(ctx context.Context, t *checks.Target) *HandshakeResult {
	res := &HandshakeResult{
		HostPort: hostPort(t),
		Probes:   make(map[uint16]*VersionProbe, len(versionsToProbe)),
	}

	for _, v := range versionsToProbe {
		probe := handshakeOne(ctx, t, res.HostPort, t.Hostname, v)
		res.Probes[v] = probe
		if probe.Supported {
			res.AnySucceeded = true
		}
	}

	// Promote the leaf/chain from the highest successful version.
	for _, v := range versionsToProbe {
		p := res.Probes[v]
		if p == nil || !p.Supported {
			continue
		}
		// Re-run a quick handshake just to retrieve the chain (the probe
		// above intentionally drops connection state to keep VersionProbe
		// small). For Phase 6 we accept the second handshake as the cost
		// of a clean separation; CacheValue ensures it happens once.
		if leaf, chain := getChain(ctx, t, res.HostPort, t.Hostname, v); leaf != nil {
			res.Leaf = leaf
			res.Chain = chain
			break
		}
	}

	res.HTTPSReachable = res.AnySucceeded

	if res.AnySucceeded {
		// Validate the chain against system roots (cert checks need this).
		if res.Leaf != nil {
			res.SystemVerifyErr = verifyChain(res.Leaf, res.Chain, t.Hostname)
		}
		// Fetch the HSTS header.
		fetchHSTS(ctx, t, res)
	}

	// Probe HTTP→HTTPS redirect regardless of HTTPS state — even when
	// HTTPS is broken we still want to know if a HTTP redirect exists.
	res.HTTPProbe = probeHTTPRedirect(ctx, t)

	return res
}

func handshakeOne(ctx context.Context, t *checks.Target, hostPort, sni string, version uint16) *VersionProbe {
	probe := &VersionProbe{Version: version}

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	rawConn, err := dialTCP(dctx, t, hostPort)
	if err != nil {
		probe.HandshakeErr = err
		return probe
	}
	defer func() { _ = rawConn.Close() }()
	if d, ok := dctx.Deadline(); ok {
		_ = rawConn.SetDeadline(d)
	}

	cfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true, //#nosec G402 -- we verify manually below
		NextProtos:         []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		probe.HandshakeErr = err
		return probe
	}
	st := tlsConn.ConnectionState()
	probe.Supported = true
	probe.NegotiatedCS = st.CipherSuite
	probe.ALPN = st.NegotiatedProtocol
	probe.OCSPStapled = len(st.OCSPResponse) > 0
	probe.PeerCertCount = len(st.PeerCertificates)
	probe.SCTs = st.SignedCertificateTimestamps
	_ = tlsConn.Close()
	return probe
}

func getChain(ctx context.Context, t *checks.Target, hostPort, sni string, version uint16) (*x509.Certificate, []*x509.Certificate) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	rawConn, err := dialTCP(dctx, t, hostPort)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = rawConn.Close() }()
	if d, ok := dctx.Deadline(); ok {
		_ = rawConn.SetDeadline(d)
	}

	cfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true, //#nosec G402 -- chain validation is performed separately
	}
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		return nil, nil
	}
	defer func() { _ = tlsConn.Close() }()
	st := tlsConn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, nil
	}
	return st.PeerCertificates[0], st.PeerCertificates
}

// dialTCP routes through safety.PinnedDial when the target has pinned
// IPs (production / API path). When PinnedIPs is empty (tests, CLI
// without --strict) it falls back to a plain net.Dialer so existing
// tests using httptest.NewUnstartedServer keep working.
func dialTCP(ctx context.Context, t *checks.Target, hostPort string) (net.Conn, error) {
	if len(t.PinnedIPs) > 0 {
		return safety.PinnedDial(ctx, "tcp", hostPort, t.Hostname, t.PinnedIPs, nil)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, "tcp", hostPort)
}

// verifyChain runs an ad-hoc x509 verification using the system trust
// store. Returns nil on success, or the verification error otherwise.
func verifyChain(leaf *x509.Certificate, chain []*x509.Certificate, sni string) error {
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       sni,
		Intermediates: intermediates,
	}
	_, err := leaf.Verify(opts)
	return err
}

func fetchHSTS(ctx context.Context, t *checks.Target, res *HandshakeResult) {
	cctx, cancel := context.WithTimeout(ctx, httpFetchTotal)
	defer cancel()

	host := t.Host
	if host == "" {
		host = t.Hostname
	}

	client := t.Client()
	if client == http.DefaultClient {
		// Build a one-shot client that won't follow redirects so we can
		// inspect HSTS on the first hop and not chase off-host links.
		client = &http.Client{
			Timeout: httpFetchTotal,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "https://"+host+"/", nil)
	req.Header.Set("User-Agent", t.UA())
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		res.HSTSErr = err
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	res.HSTSStatus = resp.StatusCode
	res.HSTSHeader = resp.Header.Get("Strict-Transport-Security")
}

func probeHTTPRedirect(ctx context.Context, t *checks.Target) *HTTPProbe {
	cctx, cancel := context.WithTimeout(ctx, httpFetchTotal)
	defer cancel()

	host := t.Host
	if host == "" {
		host = t.Hostname
	}

	noFollow := &http.Client{
		Timeout: httpFetchTotal,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "http://"+host+"/", nil)
	req.Header.Set("User-Agent", t.UA())

	resp, err := noFollow.Do(req)
	if err != nil {
		return &HTTPProbe{RedirectErr: err}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	loc := resp.Header.Get("Location")
	return &HTTPProbe{
		StatusCode: resp.StatusCode,
		Location:   loc,
		IsHTTPS:    strings.HasPrefix(strings.ToLower(loc), "https://"),
	}
}
