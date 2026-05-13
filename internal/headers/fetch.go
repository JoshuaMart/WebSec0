package headers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// fetchTimeout is the per-request budget for the header probe.
const fetchTimeout = 10 * time.Second

// fetchBodyCap is the maximum body size we read before aborting. The header
// probe does not need the body — we cap aggressively to limit exposure.
const fetchBodyCap = 64 * 1024

// Fetch issues a single GET via safehttp's pinned client and returns the
// response headers. The body is drained up to the cap and discarded.
//
// The second return is the off-host Location that ended the redirect chain
// (empty if the request stayed on-host). When safehttp rejects an off-host
// redirect, http.Client still returns the previous 3xx response — we keep
// its headers (so at least HSTS / Server land in the report) and surface
// the Location so the orchestrator can decide whether to re-probe the
// sibling host.
func Fetch(ctx context.Context, target *safehttp.Target) (http.Header, string, error) {
	client := safehttp.NewClient(safehttp.ClientOpts{
		Target:          target,
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxBodyBytes:    fetchBodyCap,
		Timeout:         fetchTimeout,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL("/"), http.NoBody)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && errors.Is(err, safehttp.ErrOffHostRedirect) {
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Header, resp.Header.Get("Location"), nil
		}
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header, "", nil
}

// Probe runs the full headers probe against target. The returned report's
// Grade and Score fields are left zero — the scoring engine fills them
// later in the pipeline. The second return mirrors Fetch's Location hint.
func Probe(ctx context.Context, target *safehttp.Target) (*scan.HeadersReport, string, error) {
	h, redirect, err := Fetch(ctx, target)
	if err != nil {
		return nil, "", err
	}
	return &scan.HeadersReport{
		Core:       EvaluateCore(h),
		Additional: EvaluateAdditional(h),
	}, redirect, nil
}
