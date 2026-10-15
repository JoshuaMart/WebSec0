package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
)

// Issuer certificates are a few KiB; the cap leaves room for PEM bundles.
const (
	maxIssuerBytes     = 64 << 10
	issuerFetchTimeout = 5 * time.Second
)

// issuerDefaultPorts lists the AIA schemes fetched and the only port each
// may use. The URL comes from the target's certificate, so custom ports
// stay refused regardless of the scan's own port policy.
var issuerDefaultPorts = map[string]int{"http": 80, "https": 443}

// fetchIssuer downloads an AIA caIssuers certificate for the TLS probe. The
// host is validated and resolved under the scan's SSRF policy, and the
// request uses the pinned safehttp client without following redirects.
func (s *Scanner) fetchIssuer(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", safehttp.ErrInvalidHost, err)
	}
	scheme := strings.ToLower(u.Scheme)
	port, ok := issuerDefaultPorts[scheme]
	if !ok {
		return nil, fmt.Errorf("%w: %q", safehttp.ErrInvalidScheme, u.Scheme)
	}
	v, err := safehttp.ValidateInput(rawURL, safehttp.InputPolicy{
		AllowedSchemes:   []string{scheme},
		AllowCustomPorts: true,
		DefaultPort:      port,
	})
	if err != nil {
		return nil, err
	}
	if v.Port != port {
		return nil, fmt.Errorf("%w: port %d", safehttp.ErrCustomPortBlocked, v.Port)
	}
	target, err := s.resolver.Resolve(ctx, v)
	if err != nil {
		return nil, err
	}

	client := safehttp.NewClient(safehttp.ClientOpts{
		Target:       target,
		MaxBodyBytes: maxIssuerBytes,
		Timeout:      issuerFetchTimeout,
	})
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch issuer: status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
