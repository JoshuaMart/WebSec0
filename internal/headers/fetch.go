package headers

import (
	"context"
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
func Fetch(ctx context.Context, target *safehttp.Target) (http.Header, error) {
	client := safehttp.NewClient(safehttp.ClientOpts{
		Target:          target,
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxBodyBytes:    fetchBodyCap,
		Timeout:         fetchTimeout,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL("/"), http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header, nil
}

// Probe runs the full headers probe against target. The returned report's
// Grade and Score fields are left zero — the scoring engine fills them
// later in the pipeline.
func Probe(ctx context.Context, target *safehttp.Target) (*scan.HeadersReport, error) {
	h, err := Fetch(ctx, target)
	if err != nil {
		return nil, err
	}
	return &scan.HeadersReport{
		Core:       EvaluateCore(h),
		Additional: EvaluateAdditional(h),
	}, nil
}
