package custom

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
)

// fetchTimeout is the per-check budget for fetching a single resource.
const fetchTimeout = 10 * time.Second

// fetchText runs a GET via safehttp's pinned client and returns the body
// (up to maxBytes), the HTTP status, and any transport error. The body cap
// prevents adversarial servers from streaming an unbounded response.
func fetchText(ctx context.Context, target *safehttp.Target, path string, maxBytes int64) (body string, status int, err error) {
	client := safehttp.NewClient(safehttp.ClientOpts{
		Target:       target,
		MaxBodyBytes: maxBytes,
		Timeout:      fetchTimeout,
	})
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, target.URL(path), http.NoBody)
	if reqErr != nil {
		return "", 0, reqErr
	}
	resp, doErr := client.Do(req)
	if doErr != nil {
		return "", 0, doErr
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body) // ErrBodyTooLarge is fine — we keep what we got.
	return string(raw), resp.StatusCode, nil
}

// mustJSON marshals v to JSON, panicking on error. Only safe with types
// the package fully controls — all Details structs here are.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
