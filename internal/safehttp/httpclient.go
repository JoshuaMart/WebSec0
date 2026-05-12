package safehttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// ClientOpts configures NewClient. Zero values are filled with conservative
// defaults — the only required field is Target.
type ClientOpts struct {
	Target          *Target
	FollowRedirects bool
	MaxRedirects    int
	MaxBodyBytes    int64 // 0 disables the cap
	Timeout         time.Duration
	DialTimeout     time.Duration

	// TLSConfig overrides the default. Default behaviour is
	// InsecureSkipVerify=true with SNI set to Target.Host — appropriate for
	// the header and custom-check probes, which must succeed even against
	// servers with bad certificates (the TLS probe grades those separately).
	TLSConfig *tls.Config
}

// NewClient builds an *http.Client wired to the safehttp guarantees:
//   - the underlying TCP dial always targets the pinned IP:port;
//   - SNI and the Host header use the original FQDN;
//   - redirects are refused when they leave the original host;
//   - response bodies are wrapped in a length-capped reader.
func NewClient(opts ClientOpts) *http.Client {
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}

	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName:         opts.Target.Host,
			InsecureSkipVerify: true, //nolint:gosec // header/custom probes must run against bad-cert hosts.
			MinVersion:         tls.VersionTLS10,
		}
	}

	base := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return PinnedDialer(opts.Target, opts.DialTimeout).DialContext(ctx, network, opts.Target.Address())
		},
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		DisableCompression:    false,
	}

	var transport http.RoundTripper = base
	if opts.MaxBodyBytes > 0 {
		transport = &cappedTransport{base: base, cap: opts.MaxBodyBytes}
	}

	check := AllowRedirect(opts.Target, opts.MaxRedirects)
	if !opts.FollowRedirects {
		check = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	return &http.Client{
		Transport:     transport,
		Timeout:       opts.Timeout,
		CheckRedirect: check,
	}
}

// cappedTransport wraps an http.RoundTripper and replaces the response
// body with a reader that aborts past the cap.
type cappedTransport struct {
	base http.RoundTripper
	cap  int64
}

func (c *cappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedReader{r: resp.Body, remaining: c.cap}
	return resp, nil
}

type cappedReader struct {
	r         io.ReadCloser
	remaining int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, ErrBodyTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

func (c *cappedReader) Close() error { return c.r.Close() }
