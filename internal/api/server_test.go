package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Jomar/websec101/internal/api"
	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/scanner"
	"github.com/Jomar/websec101/internal/scanner/safety"
	"github.com/Jomar/websec101/internal/storage/memory"
	"github.com/Jomar/websec101/internal/version"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := memory.New(time.Minute)
	registry := checks.NewRegistry()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mgr := scanner.NewManager(store, registry, scanner.ManagerConfig{}, logger)
	h, err := api.NewServer(api.Options{
		Logger:   logger,
		Store:    store,
		Registry: registry,
		Scans:    mgr,
		Policy:   safety.Permissive(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp, body
}

func TestHealth(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	resp, body := get(t, srv.URL+"/api/v1/health")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var got struct {
		Status        string `json:"status"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		Version       string `json:"version"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, body)
	}
	if got.Status != "ok" {
		t.Errorf("status = %q, want ok", got.Status)
	}
	if got.Version != version.Version {
		t.Errorf("version = %q, want %q", got.Version, version.Version)
	}
	if got.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d, want >= 0", got.UptimeSeconds)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	resp, body := get(t, srv.URL+"/api/v1/version")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var got struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildDate string `json:"build_date"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := version.Get()
	if got.Version != want.Version || got.Commit != want.Commit || got.BuildDate != want.BuildDate {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestOpenAPI(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	resp, body := get(t, srv.URL+"/api/v1/openapi.json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, _ := doc["openapi"].(string); v == "" {
		t.Errorf("missing openapi field; doc = %v", doc)
	}
	if _, ok := doc["paths"].(map[string]any); !ok {
		t.Errorf("missing paths object")
	}
}

func TestRequestIDHeaderEcho(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/health", nil)
	req.Header.Set("X-Request-ID", "abc-123-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Request-ID"); got != "abc-123-test" {
		t.Errorf("X-Request-ID = %q, want abc-123-test", got)
	}
}

func TestRequestIDGeneratedWhenAbsent(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)

	resp, _ := get(t, srv.URL+"/api/v1/health")
	if got := resp.Header.Get("X-Request-ID"); len(got) != 32 {
		t.Errorf("generated request id = %q (len=%d), want 32 hex chars", got, len(got))
	}
}

// TestMarkdownAndSARIFForUnknownScan covers the post-Phase 12 contract:
// requests for /markdown and /sarif on a non-existent scan return a
// 404 envelope (the previous 501 stub behaviour was retired once the
// reports engine landed).
func TestMarkdownAndSARIFForUnknownScan(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t)
	for _, path := range []string{
		"/api/v1/scans/00000000-0000-0000-0000-000000000000/markdown",
		"/api/v1/scans/00000000-0000-0000-0000-000000000000/sarif",
	} {
		resp, body := get(t, srv.URL+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, body = %s", path, resp.StatusCode, body)
		}
	}
}
