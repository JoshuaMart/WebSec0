package tls

import (
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// sessionResumptionTimeout caps the two-handshake probe.
const sessionResumptionTimeout = 8 * time.Second

// detectSessionResumption issues two GET requests through a transport that
// disables connection keep-alive but shares a ClientSessionCache. The
// second response's ConnectionState.DidResume tells us whether the
// server-issued ticket (or session ID) was honoured. We deliberately use
// http.Client rather than raw tls.Conn so the NewSessionTicket post-
// handshake message (TLS 1.3) has a chance to flow before we close.
func detectSessionResumption(ctx context.Context, target *safehttp.Target) scan.SessionResumption {
	cache := stdtls.NewLRUClientSessionCache(4)
	dialer := safehttp.PinnedDialer(target, 5*time.Second)

	transport := &http.Transport{
		DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(c, network, target.Address())
		},
		TLSClientConfig: &stdtls.Config{
			ServerName:         target.Host,
			InsecureSkipVerify: true, //nolint:gosec // chain validation is performed separately.
			MinVersion:         stdtls.VersionTLS12,
			MaxVersion:         stdtls.VersionTLS13,
			ClientSessionCache: cache,
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: sessionResumptionTimeout}

	// First request — primes the ClientSessionCache.
	if !sendAndDrain(ctx, client, target) {
		return scan.SessionResumptionUnknown
	}
	// Second request — should resume.
	resp, err := getRequest(ctx, client, target)
	if err != nil {
		return scan.SessionResumptionUnknown
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.TLS == nil {
		return scan.SessionResumptionUnknown
	}
	if resp.TLS.DidResume {
		return scan.SessionResumptionSupported
	}
	return scan.SessionResumptionNotSupported
}

func sendAndDrain(ctx context.Context, client *http.Client, target *safehttp.Target) bool {
	resp, err := getRequest(ctx, client, target)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return true
}

func getRequest(ctx context.Context, client *http.Client, target *safehttp.Target) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL("/"), http.NoBody)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}
