package wellknown

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/JoshuaMart/websec0/internal/checks"
)

const (
	cacheKey       = "wellknown.securitytxt"
	canonicalPath  = "/.well-known/security.txt"
	legacyPath     = "/security.txt"
	maxBodyBytes   = 64 << 10 // 64 KiB — RFC 9116 says files SHOULD be small
	defaultTimeout = 0        // honour the per-check ctx deadline
)

// FetchResult captures everything the six security.txt checks need to
// decide their finding from a single HTTP fetch.
type FetchResult struct {
	// Found is true when /.well-known/security.txt or /security.txt
	// returned a 2xx response over either scheme.
	Found bool
	// FoundOverHTTPS is true when the file was successfully retrieved
	// over HTTPS (powering the NOT-HTTPS check).
	FoundOverHTTPS bool
	// FoundOverHTTPOnly is true when the file is *only* available via
	// plain HTTP — i.e. HTTPS attempts failed but HTTP succeeded.
	FoundOverHTTPOnly bool
	// CanonicalPath is true when the file was found at /.well-known/...
	// (the RFC-mandated location); false implies the legacy /security.txt
	// fallback was used.
	CanonicalPath bool
	// FinalURL is the URL that ultimately served the file (or the last
	// URL we tried, on failure).
	FinalURL string
	// Status is the last HTTP status code observed.
	Status int
	// Body is the raw response body, truncated to maxBodyBytes.
	Body []byte
	// Parsed is non-nil when Body parsed cleanly.
	Parsed *SecurityTxt
	// Attempts records the URL + outcome of every fetch we tried, in
	// order. The MISSING check surfaces this as evidence so the operator
	// can see exactly what was probed and what status came back.
	Attempts []Attempt
	// ParseError, when non-empty, is the parse failure observed on the
	// successful 2xx body — separate from network attempts.
	ParseError string
}

// Attempt is one row of the fetch trail.
type Attempt struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

// FetchSecurityTxt is shared by every securitytxt check via target.CacheValue.
func FetchSecurityTxt(ctx context.Context, t *checks.Target) (*FetchResult, error) {
	v, err := t.CacheValue(cacheKey, func() (any, error) {
		return doFetch(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	res, _ := v.(*FetchResult)
	if res == nil {
		return nil, errors.New("fetcher: nil cached result")
	}
	return res, nil
}

func doFetch(ctx context.Context, t *checks.Target) *FetchResult {
	res := &FetchResult{}
	attempts := []struct {
		scheme    string
		path      string
		canonical bool
	}{
		{"https", canonicalPath, true},
		{"https", legacyPath, false},
		{"http", canonicalPath, true},
		{"http", legacyPath, false},
	}

	httpsAttempted := false
	httpsSucceeded := false
	httpSucceeded := false

	for _, a := range attempts {
		if a.scheme == "https" {
			httpsAttempted = true
		}
		body, status, finalURL, err := tryFetch(ctx, t, a.scheme, a.path)

		rec := Attempt{URL: finalURL}
		if err != nil {
			rec.Error = err.Error()
		} else {
			rec.Status = status
		}
		res.Attempts = append(res.Attempts, rec)

		if err == nil && status >= 200 && status < 300 {
			res.Found = true
			res.FinalURL = finalURL
			res.Status = status
			res.Body = body
			res.CanonicalPath = a.canonical
			if a.scheme == "https" {
				res.FoundOverHTTPS = true
				httpsSucceeded = true
			} else {
				httpSucceeded = true
			}
			if parsed, perr := ParseSecurityTxt(body); perr == nil {
				res.Parsed = parsed
			} else {
				res.ParseError = perr.Error()
			}
			break
		}
		if err != nil {
			continue
		}
		// Record the last non-2xx status we saw.
		res.Status = status
		res.FinalURL = finalURL
	}

	if !httpsSucceeded && httpSucceeded && httpsAttempted {
		res.FoundOverHTTPOnly = true
	}
	return res
}

// tryFetch performs one HTTP GET. It bounds the response body to
// maxBodyBytes to defend against malicious or pathological hosts.
func tryFetch(ctx context.Context, t *checks.Target, scheme, path string) (body []byte, status int, finalURL string, err error) {
	host := t.Host
	if host == "" {
		host = t.Hostname
	}
	u := url.URL{Scheme: scheme, Host: host, Path: path}
	finalURL = u.String()

	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, finalURL, nil)
	if rerr != nil {
		return nil, 0, finalURL, rerr
	}
	req.Header.Set("User-Agent", t.UA())
	req.Header.Set("Accept", "text/plain, */*;q=0.5")

	resp, derr := t.Client().Do(req)
	if derr != nil {
		return nil, 0, finalURL, derr
	}
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, maxBodyBytes)
	b, _ := io.ReadAll(limited)
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return b, resp.StatusCode, finalURL, nil
}
