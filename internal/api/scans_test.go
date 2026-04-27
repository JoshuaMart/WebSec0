package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/api"
	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/JoshuaMart/websec0/internal/scanner/safety"
	"github.com/JoshuaMart/websec0/internal/scanner/wellknown"
	"github.com/JoshuaMart/websec0/internal/storage/memory"
)

// instantCheck satisfies checks.Check and returns immediately, so the
// orchestrator can run a real-but-fast scan inside a test.
type instantCheck struct {
	id  string
	fam checks.Family
	sev checks.Severity
}

func (c instantCheck) ID() string                       { return c.id }
func (c instantCheck) Family() checks.Family            { return c.fam }
func (c instantCheck) DefaultSeverity() checks.Severity { return c.sev }
func (c instantCheck) Run(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
	return &checks.Finding{
		ID:       c.id,
		Family:   c.fam,
		Severity: c.sev,
		Status:   checks.StatusPass,
		Title:    "ok",
	}, nil
}

func newScanServer(t *testing.T, registered ...checks.Check) (*httptest.Server, *scanner.Manager) {
	t.Helper()
	store := memory.New(time.Minute)
	registry := checks.NewRegistry()
	for _, c := range registered {
		registry.Register(c)
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mgr := scanner.NewManager(store, registry, scanner.ManagerConfig{
		PerCheckTimeout: 2 * time.Second,
		PerScanTimeout:  10 * time.Second,
	}, logger)
	h, err := api.NewServer(api.Options{
		Logger:         logger,
		Store:          store,
		Registry:       registry,
		Scans:          mgr,
		Policy:         safety.Permissive(),
		PerScanTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, mgr
}

func TestCreateScanReturns202WithLocation(t *testing.T) {
	t.Parallel()
	srv, _ := newScanServer(t)

	body := strings.NewReader(`{"target":"example.com"}`)
	resp, err := http.Post(srv.URL+"/api/v1/scans", "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, out)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/api/v1/scans/") {
		t.Errorf("Location = %q", loc)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Errorf("Retry-After missing")
	}

	var sc struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Target string `json:"target"`
		Links  struct {
			Self   string `json:"self"`
			Events string `json:"events"`
		} `json:"links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sc.ID == "" || sc.Target != "example.com" {
		t.Errorf("body = %+v", sc)
	}
	if !strings.HasSuffix(sc.Links.Events, "/events") {
		t.Errorf("missing events link: %+v", sc.Links)
	}
}

func TestCreateScanRejectsEmptyTarget(t *testing.T) {
	t.Parallel()
	srv, _ := newScanServer(t)

	resp, err := http.Post(srv.URL+"/api/v1/scans", "application/json", strings.NewReader(`{"target":""}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("status = %d, want 4xx", resp.StatusCode)
	}
}

func TestPostThenGetReachesCompleted(t *testing.T) {
	t.Parallel()
	srv, _ := newScanServer(t,
		instantCheck{id: "TEST-A", fam: "tls", sev: checks.SeverityLow},
		instantCheck{id: "TEST-B", fam: "headers", sev: checks.SeverityMedium},
	)

	resp, err := http.Post(srv.URL+"/api/v1/scans", "application/json",
		strings.NewReader(`{"target":"example.com"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var sc struct {
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sc)
	resp.Body.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		gr, err := http.Get(srv.URL + sc.Links.Self)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		var got struct {
			Status   string `json:"status"`
			Findings []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"findings"`
			Progress struct {
				Total     int `json:"total"`
				Completed int `json:"completed"`
			} `json:"progress"`
		}
		_ = json.NewDecoder(gr.Body).Decode(&got)
		gr.Body.Close()
		if got.Status == "completed" {
			if len(got.Findings) != 2 {
				t.Errorf("findings = %d, want 2", len(got.Findings))
			}
			if got.Progress.Total != 2 || got.Progress.Completed != 2 {
				t.Errorf("progress = %+v", got.Progress)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("scan did not reach completed within 5s")
}

func TestSSEStreamsCompleted(t *testing.T) {
	t.Parallel()
	srv, _ := newScanServer(t,
		instantCheck{id: "SSE-A", fam: "tls", sev: checks.SeverityHigh},
	)

	pr, err := http.Post(srv.URL+"/api/v1/scans", "application/json",
		strings.NewReader(`{"target":"example.com"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var sc struct {
		Links struct {
			Events string `json:"events"`
		} `json:"links"`
	}
	_ = json.NewDecoder(pr.Body).Decode(&sc)
	pr.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+sc.Links.Events, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var sawProgress, sawFinding, sawCompleted bool
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: progress"):
			sawProgress = true
		case strings.HasPrefix(line, "event: finding"):
			sawFinding = true
		case strings.HasPrefix(line, "event: completed"):
			sawCompleted = true
		}
		if sawCompleted {
			break
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		t.Errorf("scan err: %v", err)
	}
	if !sawProgress || !sawFinding || !sawCompleted {
		t.Errorf("events seen: progress=%v finding=%v completed=%v",
			sawProgress, sawFinding, sawCompleted)
	}
}

func TestSSEReplayForFinishedScan(t *testing.T) {
	t.Parallel()
	srv, _ := newScanServer(t,
		instantCheck{id: "REPLAY-A", fam: "tls", sev: checks.SeverityLow},
	)

	pr, err := http.Post(srv.URL+"/api/v1/scans", "application/json",
		strings.NewReader(`{"target":"example.com","options":{"wait_seconds":3}}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var sc struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Links  struct {
			Events string `json:"events"`
		} `json:"links"`
	}
	_ = json.NewDecoder(pr.Body).Decode(&sc)
	pr.Body.Close()
	if sc.Status != "completed" {
		t.Fatalf("with wait_seconds=3, status = %q, want completed", sc.Status)
	}

	resp, err := http.Get(srv.URL + sc.Links.Events)
	if err != nil {
		t.Fatalf("GET events: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("event: completed")) {
		t.Errorf("replay missing completed event:\n%s", body)
	}
	if !bytes.Contains(body, []byte("event: finding")) {
		t.Errorf("replay missing finding event:\n%s", body)
	}
}

// Milestone 1: a real check (security.txt MISSING) reaches the API client
// after a POST /scans / poll-until-completed roundtrip.
func TestE2EWellKnownSecurityTxtMissing(t *testing.T) {
	t.Parallel()

	// Fixture: web root that 404s on every well-known path.
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(fixture.Close)
	targetHost := strings.TrimPrefix(fixture.URL, "http://")

	// API server with the security.txt checks registered.
	store := memory.New(time.Minute)
	registry := checks.NewRegistry()
	wellknown.Register(registry)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mgr := scanner.NewManager(store, registry, scanner.ManagerConfig{
		PerCheckTimeout: 3 * time.Second,
		PerScanTimeout:  10 * time.Second,
	}, logger)
	apiHandler, err := api.NewServer(api.Options{
		Logger: logger, Store: store, Registry: registry, Scans: mgr,
		Policy:         safety.Permissive(),
		PerScanTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv := httptest.NewServer(apiHandler)
	t.Cleanup(srv.Close)

	body := `{"target":"` + targetHost + `","options":{"wait_seconds":10}}`
	resp, err := http.Post(srv.URL+"/api/v1/scans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, out)
	}

	var sc struct {
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	gr, err := http.Get(srv.URL + sc.Links.Self)
	if err != nil {
		t.Fatalf("GET self: %v", err)
	}
	defer gr.Body.Close()
	var got struct {
		Status   string `json:"status"`
		Findings []struct {
			ID       string `json:"id"`
			Family   string `json:"family"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(gr.Body).Decode(&got); err != nil {
		t.Fatalf("decode self: %v", err)
	}
	if got.Status != "completed" {
		t.Fatalf("status = %q", got.Status)
	}
	if len(got.Findings) != 6 {
		t.Errorf("findings = %d, want 6 (one per security.txt check)", len(got.Findings))
	}

	byID := map[string]string{}
	for _, f := range got.Findings {
		byID[f.ID] = f.Status
		if f.Family != "wellknown" {
			t.Errorf("%s family = %q, want wellknown", f.ID, f.Family)
		}
	}
	if byID[wellknown.IDMissing] != "fail" {
		t.Errorf("MISSING status = %q, want fail (no security.txt)", byID[wellknown.IDMissing])
	}
	// All dependent checks must skip gracefully when the file is absent.
	for _, id := range []string{wellknown.IDExpired, wellknown.IDNoContact, wellknown.IDNoExpires, wellknown.IDNoSignature} {
		if byID[id] != "skipped" {
			t.Errorf("%s = %q, want skipped", id, byID[id])
		}
	}
}

func TestListChecksReturnsCatalog(t *testing.T) {
	t.Parallel()
	srv, _ := newScanServer(t,
		instantCheck{id: "CAT-Z", fam: "tls", sev: checks.SeverityLow},
		instantCheck{id: "CAT-A", fam: "dns", sev: checks.SeverityHigh},
	)

	resp, err := http.Get(srv.URL + "/api/v1/checks")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	var got []struct {
		ID              string `json:"id"`
		Family          string `json:"family"`
		DefaultSeverity string `json:"default_severity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].ID != "CAT-A" || got[1].ID != "CAT-Z" {
		t.Errorf("catalog = %+v", got)
	}
}
