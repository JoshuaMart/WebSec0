package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	ogenhttp "github.com/ogen-go/ogen/http"
	ogenerrors "github.com/ogen-go/ogen/ogenerrors"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/report"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/JoshuaMart/websec0/internal/scanner/safety"
	"github.com/JoshuaMart/websec0/internal/storage"
	"github.com/JoshuaMart/websec0/internal/storage/memory"
	client "github.com/JoshuaMart/websec0/pkg/client"
)

// --- New & defaults --------------------------------------------------

func TestNew_AppliesDefaults(t *testing.T) {
	h := New(Options{})
	if h.policy == nil {
		t.Error("Policy default not applied")
	}
	if h.perScanTimeout != 120*time.Second {
		t.Errorf("PerScanTimeout default = %s, want 120s", h.perScanTimeout)
	}
	if h.startedAt.IsZero() {
		t.Error("startedAt not set")
	}
}

// --- GetHealth / GetVersion / GetOpenAPI -----------------------------

func TestGetHealth(t *testing.T) {
	h := New(Options{})
	got, err := h.GetHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != client.HealthStatusOk {
		t.Errorf("Status = %v, want ok", got.Status)
	}
	if got.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds = %d, want ≥ 0", got.UptimeSeconds)
	}
}

func TestGetVersion(t *testing.T) {
	h := New(Options{})
	got, err := h.GetVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Version may be "dev" without ldflags — only assert non-nil.
	_ = got.Version
}

func TestGetOpenAPI(t *testing.T) {
	h := New(Options{})
	got, err := h.GetOpenAPI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["openapi"]; !ok {
		t.Errorf("response missing 'openapi' key, got keys=%v", keys(got))
	}
}

// --- ListChecks / GetCheck -------------------------------------------

func TestListChecks_Empty(t *testing.T) {
	h := New(Options{Registry: checks.NewRegistry()})
	got, err := h.ListChecks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestListChecks_NilRegistry(t *testing.T) {
	h := New(Options{})
	got, err := h.ListChecks(context.Background())
	if err != nil || len(got) != 0 {
		t.Errorf("got %v err=%v, want empty list", got, err)
	}
}

func TestListChecks_WithEntries(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(stubCheck{})
	h := New(Options{Registry: r})
	got, _ := h.ListChecks(context.Background())
	if len(got) != 1 || got[0].ID != "STUB-CHECK" {
		t.Errorf("ListChecks = %+v, want [STUB-CHECK]", got)
	}
	if got[0].Title.Value != "stub" || got[0].Description.Value != "stub description" {
		t.Errorf("Describer not propagated: %+v", got[0])
	}
}

func TestGetCheck_KnownAndUnknown(t *testing.T) {
	r := checks.NewRegistry()
	r.Register(stubCheck{})
	h := New(Options{Registry: r})

	res, err := h.GetCheck(context.Background(), client.GetCheckParams{CheckID: "STUB-CHECK"})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := res.(*client.Check)
	if !ok {
		t.Fatalf("type = %T, want *client.Check", res)
	}
	if c.ID != "STUB-CHECK" {
		t.Errorf("ID = %s", c.ID)
	}

	res, _ = h.GetCheck(context.Background(), client.GetCheckParams{CheckID: "DOES-NOT-EXIST"})
	if got := statusOf(res); got != 404 {
		t.Errorf("unknown check status = %d, want 404", got)
	}
}

func TestGetCheck_NilRegistry(t *testing.T) {
	h := New(Options{})
	res, _ := h.GetCheck(context.Background(), client.GetCheckParams{CheckID: "X"})
	if got := statusOf(res); got != 404 {
		t.Errorf("status = %d, want 404", got)
	}
}

// --- CreateScan: shallow paths ---------------------------------------

func TestCreateScan_NoScansWired(t *testing.T) {
	h := New(Options{})
	res, _ := h.CreateScan(context.Background(), &client.ScanRequest{Target: "example.com"})
	if got := statusOf(res); got != 501 {
		t.Errorf("status = %d, want 501", got)
	}
}

func TestCreateScan_EmptyTarget(t *testing.T) {
	h := New(Options{Scans: noopScanService{}})
	res, _ := h.CreateScan(context.Background(), &client.ScanRequest{Target: ""})
	if got := statusOf(res); got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
	res, _ = h.CreateScan(context.Background(), nil)
	if got := statusOf(res); got != 400 {
		t.Errorf("nil request status = %d, want 400", got)
	}
}

func TestCreateScan_InvalidTarget(t *testing.T) {
	h := New(Options{Scans: noopScanService{}})
	res, _ := h.CreateScan(context.Background(), &client.ScanRequest{Target: "http://[bad"})
	if got := statusOf(res); got != 422 {
		t.Errorf("status = %d, want 422", got)
	}
}

// TestCreateScan_BlockedDomain exercises the safety policy blocklist
// gate. The default policy rejects a `.gov` target with HTTP 451.
func TestCreateScan_BlockedDomain(t *testing.T) {
	policy := safety.Default()
	policy.DomainBlocklist = append(policy.DomainBlocklist, ".gov.invalid")
	h := New(Options{
		Scans:  noopScanService{},
		Policy: policy,
	})
	res, _ := h.CreateScan(context.Background(), &client.ScanRequest{Target: "agency.gov.invalid"})
	if got := statusOf(res); got != 451 {
		t.Errorf("status = %d, want 451 (blocklist)", got)
	}
}

// TestCreateScan_SuccessReturnsCreated drives the success path with a
// loopback target + Permissive policy that accepts 127.0.0.1.
func TestCreateScan_SuccessReturnsCreated(t *testing.T) {
	policy := safety.Permissive()
	if !policy.AddAllowedCIDR("127.0.0.0/8") {
		t.Fatal("AddAllowedCIDR returned false")
	}

	h := New(Options{
		Store:  memory.New(time.Hour),
		Scans:  noopScanService{},
		Policy: policy,
	})
	res, err := h.CreateScan(context.Background(), &client.ScanRequest{Target: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	created, ok := res.(*client.ScanCreatedHeaders)
	if !ok {
		t.Fatalf("type = %T, want *ScanCreatedHeaders (got status=%d)", res, statusOf(res))
	}
	if loc, ok := created.Location.Get(); !ok || !strings.Contains(loc, "/api/v1/scans/") {
		t.Errorf("Location header = %q", loc)
	}
	if r, ok := created.RetryAfter.Get(); !ok || r <= 0 {
		t.Errorf("Retry-After = %d, want > 0", r)
	}
}

// --- GetScan / DeleteScan / GetScanMarkdown / GetScanSARIF -----------

func TestGetScan_NotFound(t *testing.T) {
	h := New(Options{Store: memory.New(time.Hour)})
	res, _ := h.GetScan(context.Background(), client.GetScanParams{GUID: uuid.New()})
	if got := statusOf(res); got != 404 {
		t.Errorf("status = %d, want 404", got)
	}
}

func TestGetScan_FoundReturnsScan(t *testing.T) {
	store := memory.New(time.Hour)
	id := uuid.New()
	rep := &report.Report{Summary: report.Summary{Grade: "A", Score: 95}}
	_ = store.Put(context.Background(), &storage.Scan{
		ID:        id.String(),
		Status:    storage.StatusCompleted,
		Target:    "example.com",
		StartedAt: time.Now().UTC(),
		Report:    rep,
	}, time.Hour)

	h := New(Options{Store: store})
	res, err := h.GetScan(context.Background(), client.GetScanParams{GUID: id})
	if err != nil {
		t.Fatal(err)
	}
	s, ok := res.(*client.Scan)
	if !ok {
		t.Fatalf("res type = %T, want *client.Scan", res)
	}
	if s.Target != "example.com" {
		t.Errorf("Target = %s", s.Target)
	}
	if g, _ := s.Grade.Get(); g != "A" {
		t.Errorf("Grade = %q, want A", g)
	}
}

func TestGetScan_PropagatesFindingsAndProgress(t *testing.T) {
	store := memory.New(time.Hour)
	id := uuid.New()
	completedAt := time.Now().UTC()
	_ = store.Put(context.Background(), &storage.Scan{
		ID:          id.String(),
		Status:      storage.StatusCompleted,
		Target:      "example.com",
		StartedAt:   completedAt.Add(-time.Minute),
		CompletedAt: &completedAt,
		Progress:    storage.Progress{Total: 2, Completed: 2, CurrentPhase: "tls"},
		Findings: []checks.Finding{
			{
				ID: "TLS-HSTS-MISSING", Family: checks.FamilyTLS,
				Severity: checks.SeverityHigh, Status: checks.StatusFail,
				Title:       "no HSTS header",
				Description: "Strict-Transport-Security missing",
				Evidence:    map[string]any{"header_present": false},
				Remediation: map[string]any{
					"summary": "Add HSTS header",
					"snippets": map[string]any{
						"nginx": "add_header Strict-Transport-Security ...",
					},
				},
			},
		},
		Error: "transient lookup failure",
	}, time.Hour)

	h := New(Options{Store: store})
	res, err := h.GetScan(context.Background(), client.GetScanParams{GUID: id})
	if err != nil {
		t.Fatal(err)
	}
	s := res.(*client.Scan)

	if len(s.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(s.Findings))
	}
	f := s.Findings[0]
	if f.ID != "TLS-HSTS-MISSING" {
		t.Errorf("Findings[0].ID = %s", f.ID)
	}
	if ev, ok := f.Evidence.Get(); !ok || len(ev) == 0 {
		t.Errorf("Evidence not propagated: %+v", f.Evidence)
	}
	if rm, ok := f.Remediation.Get(); !ok || len(rm) == 0 {
		t.Errorf("Remediation not propagated: %+v", f.Remediation)
	}

	if p, ok := s.Progress.Get(); !ok {
		t.Error("Progress missing")
	} else if p.Total != 2 || p.Completed != 2 {
		t.Errorf("Progress = %+v, want {2,2,tls}", p)
	}

	if errMsg, ok := s.Error.Get(); !ok || errMsg == "" {
		t.Errorf("Error not propagated: %q ok=%v", errMsg, ok)
	}
}

func TestJsonRaw_HandlesUnencodableValue(t *testing.T) {
	// json.Marshal cannot encode chan; jsonRaw must fall back to "null".
	got := jsonRaw(make(chan int))
	if string(got) != "null" {
		t.Errorf("jsonRaw(unencodable) = %q, want null", got)
	}
	// Sanity: scalar round-trips.
	got = jsonRaw("hello")
	if string(got) != `"hello"` {
		t.Errorf("jsonRaw(\"hello\") = %q", got)
	}
}

func TestDeleteScan(t *testing.T) {
	store := memory.New(time.Hour)
	id := uuid.New()
	_ = store.Put(context.Background(), &storage.Scan{ID: id.String(), Status: storage.StatusCompleted}, time.Hour)
	h := New(Options{Store: store})

	res, _ := h.DeleteScan(context.Background(), client.DeleteScanParams{GUID: id})
	if _, ok := res.(*client.DeleteScanNoContent); !ok {
		t.Errorf("res type = %T, want NoContent", res)
	}
	// Now missing → 404.
	res, _ = h.DeleteScan(context.Background(), client.DeleteScanParams{GUID: id})
	if got := statusOf(res); got != 404 {
		t.Errorf("status = %d, want 404", got)
	}
}

func TestGetScanMarkdown_NotFoundAndNotComplete(t *testing.T) {
	store := memory.New(time.Hour)
	id := uuid.New()
	h := New(Options{Store: store})

	res, _ := h.GetScanMarkdown(context.Background(), client.GetScanMarkdownParams{GUID: uuid.New()})
	if got := statusOf(res); got != 404 {
		t.Errorf("not-found status = %d, want 404", got)
	}

	_ = store.Put(context.Background(), &storage.Scan{ID: id.String(), Status: storage.StatusRunning}, time.Hour)
	res, _ = h.GetScanMarkdown(context.Background(), client.GetScanMarkdownParams{GUID: id})
	if got := statusOf(res); got != 409 {
		t.Errorf("not-completed status = %d, want 409", got)
	}
}

func TestGetScanMarkdown_Completed(t *testing.T) {
	store := memory.New(time.Hour)
	id := uuid.New()
	rep := &report.Report{
		Scan:    report.ScanInfo{Target: "example.com", StartedAt: time.Now().UTC()},
		Summary: report.Summary{Grade: "A", Score: 90},
	}
	_ = store.Put(context.Background(), &storage.Scan{
		ID: id.String(), Status: storage.StatusCompleted, Target: "example.com", Report: rep,
	}, time.Hour)
	h := New(Options{Store: store})

	res, err := h.GetScanMarkdown(context.Background(), client.GetScanMarkdownParams{GUID: id})
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := res.(*client.GetScanMarkdownOK)
	if ok == nil {
		t.Fatalf("type = %T, want *GetScanMarkdownOK", res)
	}
	body, _ := io.ReadAll(ok.Data)
	if !strings.Contains(string(body), "Grade") {
		t.Errorf("rendered markdown does not mention Grade:\n%s", body)
	}
}

func TestGetScanSARIF_Completed(t *testing.T) {
	store := memory.New(time.Hour)
	id := uuid.New()
	rep := &report.Report{
		Scan:    report.ScanInfo{Target: "example.com", ScannerVersion: "test"},
		Summary: report.Summary{Grade: "A", Score: 90},
	}
	_ = store.Put(context.Background(), &storage.Scan{
		ID: id.String(), Status: storage.StatusCompleted, Target: "example.com", Report: rep,
	}, time.Hour)
	h := New(Options{Store: store})

	res, err := h.GetScanSARIF(context.Background(), client.GetScanSARIFParams{GUID: id})
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := res.(*client.GetScanSARIFOK)
	if ok == nil {
		t.Fatalf("type = %T, want *GetScanSARIFOK", res)
	}
	if _, has := (*ok)["runs"]; !has {
		t.Error("SARIF body missing 'runs' key")
	}
}

func TestGetScanSARIF_FailedAndNotFound(t *testing.T) {
	store := memory.New(time.Hour)
	id := uuid.New()
	_ = store.Put(context.Background(), &storage.Scan{ID: id.String(), Status: storage.StatusFailed, Error: "boom"}, time.Hour)
	h := New(Options{Store: store})

	res, _ := h.GetScanSARIF(context.Background(), client.GetScanSARIFParams{GUID: id})
	if got := statusOf(res); got != 409 {
		t.Errorf("failed status = %d, want 409", got)
	}
	res, _ = h.GetScanSARIF(context.Background(), client.GetScanSARIFParams{GUID: uuid.New()})
	if got := statusOf(res); got != 404 {
		t.Errorf("not-found status = %d, want 404", got)
	}
}

// --- ErrorHandler -----------------------------------------------------

func TestErrorHandler_NotImplemented(t *testing.T) {
	rec := httptest.NewRecorder()
	ErrorHandler(context.Background(), rec, httptest.NewRequest("GET", "/", nil), ogenhttp.ErrNotImplemented)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not_implemented") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestErrorHandler_DecodeError(t *testing.T) {
	rec := httptest.NewRecorder()
	ErrorHandler(
		context.Background(),
		rec,
		httptest.NewRequest("GET", "/", nil),
		&ogenerrors.DecodeRequestError{Err: errors.New("bad json")},
	)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestErrorHandler_GenericIs500(t *testing.T) {
	rec := httptest.NewRecorder()
	ErrorHandler(context.Background(), rec, httptest.NewRequest("GET", "/", nil), errors.New("boom"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal_error") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// --- helpers / stubs --------------------------------------------------

type stubCheck struct{}

func (stubCheck) ID() string                       { return "STUB-CHECK" }
func (stubCheck) Family() checks.Family            { return checks.FamilyTLS }
func (stubCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (stubCheck) Run(_ context.Context, _ *checks.Target) (*checks.Finding, error) {
	return &checks.Finding{ID: "STUB-CHECK", Status: checks.StatusPass}, nil
}
func (stubCheck) Title() string         { return "stub" }
func (stubCheck) Description() string   { return "stub description" }
func (stubCheck) RFCRefs() []string     { return []string{"RFC TEST"} }

type noopScanService struct{}

func (noopScanService) CreateScan(_ context.Context, _ *checks.Target, _ time.Duration) (*storage.Scan, error) {
	return &storage.Scan{ID: "noop"}, nil
}
func (noopScanService) Subscribe(_ string) (<-chan scanner.Event, func(), error) {
	ch := make(chan scanner.Event)
	close(ch)
	return ch, func() {}, nil
}

func statusOf(res any) int {
	if e, ok := res.(*client.ErrorStatusCode); ok {
		return e.StatusCode
	}
	return 0
}

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// silence unused-import warnings if a helper stops being referenced.
var _ = safety.Permissive
