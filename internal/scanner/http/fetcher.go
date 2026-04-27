// Package http implements the Web/Custom family of WebSec101 checks
// (HTTP/2-3, mixed content, dangerous methods, CORS, 404 hygiene,
// compression, robots.txt, change-password well-known, SRI).
//
// The homepage GET is shared with internal/scanner/headers via
// headers.Fetch; the additional probes (OPTIONS / TRACE / CORS /
// 404 / robots / change-password) are batched and memoised here.
package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
)

const (
	cacheKey = "http.aux"
	totalTO  = 8 * time.Second
	maxBody  = 256 << 10
)

// AuxResult batches every auxiliary probe.
type AuxResult struct {
	Options     *Probe
	Trace       *Probe
	CORSReflect *Probe
	CORSNull    *Probe
	NotFound    *Probe
	Robots      *Probe
	ChangePass  *Probe
}

// Probe is a single response snapshot.
type Probe struct {
	URL     string
	Status  int
	Headers http.Header
	Body    []byte
	Err     error
}

// Fetch runs (or memoises) the auxiliary probes for t.
func Fetch(ctx context.Context, t *checks.Target) (*AuxResult, error) {
	v, err := t.CacheValue(cacheKey, func() (any, error) {
		return doFetch(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	r, _ := v.(*AuxResult)
	if r == nil {
		return nil, errors.New("http: nil cached aux result")
	}
	return r, nil
}

func client(t *checks.Target) *http.Client {
	// We always force CheckRedirect=ErrUseLastResponse so 3xx responses
	// (e.g. /.well-known/change-password) are visible to the check.
	// Re-wrap the user-supplied client to preserve its TLS config.
	c := t.Client()
	wrapped := &http.Client{
		Timeout:   totalTO,
		Transport: c.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return wrapped
}

func doFetch(ctx context.Context, t *checks.Target) *AuxResult {
	host := t.Host
	if host == "" {
		host = t.Hostname
	}
	base := "https://" + host

	res := &AuxResult{}
	cl := client(t)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		res.Options = probe(ctx, cl, t, http.MethodOptions, base+"/", nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		res.Trace = probe(ctx, cl, t, http.MethodTrace, base+"/", nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		res.CORSReflect = probe(ctx, cl, t, http.MethodGet, base+"/",
			map[string]string{"Origin": "https://websec0-test.invalid"})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		res.CORSNull = probe(ctx, cl, t, http.MethodGet, base+"/",
			map[string]string{"Origin": "null"})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		path := fmt.Sprintf("/websec0-test-%d", time.Now().UnixNano())
		res.NotFound = probe(ctx, cl, t, http.MethodGet, base+path, nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		res.Robots = probe(ctx, cl, t, http.MethodGet, base+"/robots.txt", nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		res.ChangePass = probe(ctx, cl, t, http.MethodGet, base+"/.well-known/change-password", nil)
	}()
	wg.Wait()
	return res
}

func probe(ctx context.Context, cl *http.Client, t *checks.Target, method, url string, headers map[string]string) *Probe {
	cctx, cancel := context.WithTimeout(ctx, totalTO)
	defer cancel()
	p := &Probe{URL: url}
	req, err := http.NewRequestWithContext(cctx, method, url, nil)
	if err != nil {
		p.Err = err
		return p
	}
	req.Header.Set("User-Agent", t.UA())
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := cl.Do(req)
	if err != nil {
		p.Err = err
		return p
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	p.Status = resp.StatusCode
	p.Headers = resp.Header
	p.Body = body
	return p
}
