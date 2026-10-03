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

// Options controls header-probe redirects. Zero values disable redirects.
type Options struct {
	FollowRedirects bool
	MaxRedirects    int
}

// Redirect describes an off-host redirect and its remaining hop budget.
type Redirect struct {
	Location  string
	Remaining int
}

// Fetch returns response headers and any off-host redirect for the orchestrator.
func Fetch(ctx context.Context, target *safehttp.Target, opts Options) (http.Header, *Redirect, error) {
	client := safehttp.NewClient(safehttp.ClientOpts{
		Target:          target,
		FollowRedirects: opts.FollowRedirects,
		MaxRedirects:    opts.MaxRedirects,
		MaxBodyBytes:    fetchBodyCap,
		Timeout:         fetchTimeout,
	})
	defer client.CloseIdleConnections()
	remaining := opts.MaxRedirects
	check := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		remaining = opts.MaxRedirects - len(via)
		return check(req, via)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL("/"), http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && errors.Is(err, safehttp.ErrOffHostRedirect) {
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Header, &Redirect{Location: resp.Header.Get("Location"), Remaining: remaining}, nil
		}
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Header, nil, nil
}

// Probe runs the full headers probe against target. The returned report's
// Grade and Score fields are left zero — the scoring engine fills them
// later in the pipeline. The second return mirrors Fetch's Location hint.
func Probe(ctx context.Context, target *safehttp.Target, opts Options) (*scan.HeadersReport, *Redirect, error) {
	h, redirect, err := Fetch(ctx, target, opts)
	if err != nil {
		return nil, nil, err
	}
	return &scan.HeadersReport{
		Core:       EvaluateCore(h),
		Additional: EvaluateAdditional(h),
	}, redirect, nil
}
