// Package headers implements the HTTP-headers family of WebSec101
// checks. All checks share a single homepage fetch via Target.CacheValue.
package headers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Jomar/websec101/internal/checks"
)

const (
	cacheKey  = "headers.homepage"
	totalTO   = 10 * time.Second
	maxBody   = 256 << 10 // 256 KiB cap on body capture
	maxRedirs = 5
)

// FetchResult is the captured homepage response.
type FetchResult struct {
	Reachable bool
	URL       string
	Status    int
	// ProtoMajor / ProtoMinor capture the negotiated HTTP version
	// (e.g. 2/0 for HTTP/2). resp.Proto contains a "HTTP/2.0" string.
	ProtoMajor int
	ProtoMinor int
	Headers    http.Header
	Body       []byte
	Err        error
}

// Header returns the first value of name (case-insensitive) or "".
func (f *FetchResult) Header(name string) string {
	if f == nil || f.Headers == nil {
		return ""
	}
	return f.Headers.Get(name)
}

// AllHeaders returns every value of name. Some headers (Set-Cookie,
// CSP-Report-Only, etc.) may legitimately appear multiple times.
func (f *FetchResult) AllHeaders(name string) []string {
	if f == nil || f.Headers == nil {
		return nil
	}
	return f.Headers.Values(name)
}

// Fetch performs a single HTTPS GET on the target's root and memoises
// the result on the Target.
func Fetch(ctx context.Context, t *checks.Target) (*FetchResult, error) {
	v, err := t.CacheValue(cacheKey, func() (any, error) {
		return doFetch(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	res, _ := v.(*FetchResult)
	if res == nil {
		return nil, errors.New("headers: nil cached result")
	}
	return res, nil
}

func doFetch(ctx context.Context, t *checks.Target) *FetchResult {
	res := &FetchResult{}

	host := t.Host
	if host == "" {
		host = t.Hostname
	}

	cctx, cancel := context.WithTimeout(ctx, totalTO)
	defer cancel()

	client := t.Client()
	if client == http.DefaultClient {
		// Disable transparent gzip decoding so HTTP-COMPRESSION-NONE can
		// observe the original Content-Encoding header. The default
		// Transport sets Accept-Encoding for us and decodes silently.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DisableCompression = true
		client = &http.Client{
			Timeout:   totalTO,
			Transport: tr,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirs {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		res.Err = err
		return res
	}
	req.Header.Set("User-Agent", t.UA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.5")
	// Explicit Accept-Encoding so servers compress and DisableCompression
	// (set above) keeps the Content-Encoding header visible to us.
	req.Header.Set("Accept-Encoding", "gzip, br, deflate")

	resp, err := client.Do(req)
	if err != nil {
		res.Err = err
		return res
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	res.Reachable = true
	res.Status = resp.StatusCode
	res.ProtoMajor = resp.ProtoMajor
	res.ProtoMinor = resp.ProtoMinor
	res.Headers = resp.Header
	res.Body = body
	if resp.Request != nil && resp.Request.URL != nil {
		res.URL = resp.Request.URL.String()
	}
	return res
}
