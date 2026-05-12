package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
	"github.com/JoshuaMart/websec0/internal/scanner"
)

// fakeScanner is the in-memory ScanService used by API tests. It avoids
// the real DNS + probe pipeline entirely.
type fakeScanner struct {
	runFunc func(context.Context, scanner.Request) (*scan.Result, error)
	store   map[string]*scan.Result
}

func (f *fakeScanner) Run(ctx context.Context, req scanner.Request) (*scan.Result, error) {
	if f.runFunc == nil {
		return &scan.Result{ID: "stub", Host: req.Host, Port: req.Port}, nil
	}
	return f.runFunc(ctx, req)
}

func (f *fakeScanner) Get(id string) (*scan.Result, bool) {
	r, ok := f.store[id]
	return r, ok
}

func newTestServer(t *testing.T, s ScanService) *httptest.Server {
	t.Helper()
	r := NewRouter(Deps{
		Scanner: s,
		Config:  config.Defaults(),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func postScan(t *testing.T, srv *httptest.Server, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(srv.URL+"/api/v1/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readErrorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body errorBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return body.Error.Code
}

func TestScanPost_RejectsInvalidJSON(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{})
	resp := postScan(t, srv, "{not json")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
	if code := readErrorCode(t, resp); code != "invalid_json" {
		t.Errorf("code: got %s, want invalid_json", code)
	}
}

func TestScanPost_RejectsUnknownFields(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{})
	resp := postScan(t, srv, `{"host":"example.com","weird":1}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
}

func TestScanPost_RejectsEmptyHost(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{})
	resp := postScan(t, srv, `{"host":""}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", resp.StatusCode)
	}
	if code := readErrorCode(t, resp); code != "invalid_host" {
		t.Errorf("code: got %s, want invalid_host", code)
	}
}

func TestScanPost_MapsTypedErrors(t *testing.T) {
	cases := []struct {
		name   string
		retErr error
		status int
		code   string
	}{
		{"invalid scheme", safehttp.ErrInvalidScheme, 400, "invalid_scheme"},
		{"ip literal", safehttp.ErrIPLiteral, 400, "ip_literal"},
		{"custom port blocked", safehttp.ErrCustomPortBlocked, 403, "custom_port_blocked"},
		{"private target blocked", safehttp.ErrPrivateTargetBlocked, 403, "private_target_blocked"},
		{"no allowed ip", safehttp.ErrNoAllowedIP, 502, "no_allowed_ip"},
		{"deadline", context.DeadlineExceeded, 408, "scan_timeout"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := &fakeScanner{runFunc: func(context.Context, scanner.Request) (*scan.Result, error) {
				return nil, c.retErr
			}}
			srv := newTestServer(t, fs)
			resp := postScan(t, srv, `{"host":"example.com"}`)
			if resp.StatusCode != c.status {
				t.Errorf("status: got %d, want %d", resp.StatusCode, c.status)
			}
			if code := readErrorCode(t, resp); code != c.code {
				t.Errorf("code: got %s, want %s", code, c.code)
			}
		})
	}
}

func TestScanPost_HappyPathReturnsBody(t *testing.T) {
	fs := &fakeScanner{runFunc: func(_ context.Context, req scanner.Request) (*scan.Result, error) {
		return &scan.Result{
			ID:     "abc",
			Host:   req.Host,
			Port:   443,
			Custom: []scan.CustomFinding{{ID: "custom.security_txt", Title: "security.txt", Status: scan.StatusPass}},
		}, nil
	}}
	srv := newTestServer(t, fs)
	resp := postScan(t, srv, `{"host":"example.com"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	var got scan.Result
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "abc" || got.Host != "example.com" {
		t.Errorf("got %+v", got)
	}
}

func TestScanGet_NotFound(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{store: map[string]*scan.Result{}})
	resp, _ := http.Get(srv.URL + "/api/v1/scan/missing")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", resp.StatusCode)
	}
	if code := readErrorCode(t, resp); code != "not_found" {
		t.Errorf("code: got %s, want not_found", code)
	}
}

func TestScanGet_HitReturnsCachedResult(t *testing.T) {
	want := &scan.Result{ID: "abc", Host: "example.com", Port: 443}
	srv := newTestServer(t, &fakeScanner{store: map[string]*scan.Result{"abc": want}})
	resp, _ := http.Get(srv.URL + "/api/v1/scan/abc")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	var got scan.Result
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.ID != "abc" {
		t.Errorf("got %+v", got)
	}
}

func TestChecks_ReturnsStubCatalog(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{})
	resp, _ := http.Get(srv.URL + "/api/v1/checks")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	var p checksPayload
	_ = json.NewDecoder(resp.Body).Decode(&p)
	if p.Version == "" {
		t.Error("version should be set")
	}
}

func TestRouter_RejectsUnknownRoute(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{})
	resp, _ := http.Get(srv.URL + "/api/v2/nope")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", resp.StatusCode)
	}
	if code := readErrorCode(t, resp); code != "not_found" {
		t.Errorf("code: got %s, want not_found", code)
	}
}

func TestRateLimit_TripsAfterBurst(t *testing.T) {
	// Tight per-IP limit so the test trips deterministically. The default
	// per-host limit (1/minute) would otherwise trip first because every
	// request targets the same host.
	cfg := config.Defaults()
	cfg.History.RateLimit.PerIP.Count = 2
	cfg.History.RateLimit.PerIP.Period = time.Hour
	cfg.History.RateLimit.PerHost.Count = 100
	cfg.History.RateLimit.PerHost.Period = time.Hour

	r := NewRouter(Deps{
		Scanner: &fakeScanner{},
		Config:  cfg,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	send := func() *http.Response {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/scan", bytes.NewBufferString(`{"host":"example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := http.DefaultClient.Do(req)
		return resp
	}
	for i := 0; i < 2; i++ {
		resp := send()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d should have passed, got 429", i)
		}
		_ = resp.Body.Close()
	}
	resp := send()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("3rd request: got %d, want 429", resp.StatusCode)
	}
	if code := readErrorCode(t, resp); code != "rate_limited" {
		t.Errorf("code: got %s, want rate_limited", code)
	}
}
