package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-faster/jx"
	"github.com/google/uuid"

	"github.com/Jomar/websec101/internal/api/middleware"
	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/scanner"
	"github.com/Jomar/websec101/internal/scanner/safety"
	"github.com/Jomar/websec101/internal/storage"
	client "github.com/Jomar/websec101/pkg/client"
)

// ScanService is what the handler needs from the scanner package — kept
// as an interface so tests can swap it.
type ScanService interface {
	CreateScan(ctx context.Context, target *checks.Target, scanTimeout time.Duration) (*storage.Scan, error)
	Subscribe(id string) (<-chan scanner.Event, func(), error)
}

// CreateScan implements POST /api/v1/scans.
func (h *Handler) CreateScan(ctx context.Context, req *client.ScanRequest) (client.CreateScanRes, error) {
	if h.scans == nil {
		return errEnvelope(501, "not_implemented", "scans not wired"), nil
	}
	if req == nil || req.Target == "" {
		return errEnvelope(400, "bad_request", "target is required"), nil
	}

	target, err := checks.NewTarget(req.Target, nil)
	if err != nil {
		return errEnvelope(422, "invalid_target", err.Error()), nil
	}

	srcIP := middleware.SourceIPFromContext(ctx)

	// Anti-SSRF + DNS-rebinding gate: resolve once, pin the IP set.
	pinned, decision := safety.ResolveAndValidate(ctx, target.Hostname, h.policy, nil)
	if decision != nil {
		h.audit("blocked", srcIP, target.Hostname, "", string(decision.Reason))
		status := 422
		if decision.Reason == safety.ReasonDomainBlocked {
			status = 451
		}
		return errEnvelope(status, "target_blocked", decision.HumanError()), nil
	}
	target.PinnedIPs = pinned
	target.HTTPClient = safety.HTTPClient(target.Hostname, pinned, h.policy)

	// Cooldown / cache / abuse pattern.
	if h.tracker != nil {
		dec := h.tracker.PreScan(srcIP, target.Hostname, false)
		switch {
		case dec.AbuseFlagged:
			h.audit("abuse_flagged", srcIP, target.Hostname, "", "fanout_exceeded")
			return errEnvelope(429, "abuse_flagged",
				"too many distinct targets from this source — slow down"), nil
		case dec.CachedScanID != "":
			h.audit("cached", srcIP, target.Hostname, dec.CachedScanID, "")
			cached, gerr := h.store.Get(ctx, dec.CachedScanID)
			if gerr == nil {
				return h.toScanCreated(cached), nil
			}
			// Cache pointed at a now-evicted scan; fall through and create.
		case dec.CooldownLeft > 0:
			h.audit("cooldown", srcIP, target.Hostname, "", "")
			return errEnvelope(429, "cooldown",
				"target was scanned recently; retry later"), nil
		}
	}

	wait := 0
	if opts, ok := req.Options.Get(); ok {
		if w, ok := opts.WaitSeconds.Get(); ok {
			wait = w
		}
	}

	scan, err := h.scans.CreateScan(ctx, target, h.perScanTimeout)
	if err != nil {
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	if h.tracker != nil {
		h.tracker.Record(target.Hostname, scan.ID)
	}
	h.audit("accepted", srcIP, target.Hostname, scan.ID, "")

	if wait > 0 {
		if w := time.Duration(wait) * time.Second; w > 0 {
			scan = h.waitForCompletion(scan.ID, w)
		}
	}

	return h.toScanCreated(scan), nil
}

// GetScan implements GET /api/v1/scans/{guid} (always 200 if known).
func (h *Handler) GetScan(ctx context.Context, params client.GetScanParams) (client.GetScanRes, error) {
	scan, err := h.store.Get(ctx, params.GUID.String())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return errEnvelope(404, "not_found", "scan not found"), nil
		}
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	return h.toClientScan(scan), nil
}

// DeleteScan implements DELETE /api/v1/scans/{guid}.
//
// NOTE: ogen drops the Authorization header parameter from the OpenAPI
// spec because it conflicts with security-scheme handling. Private-mode
// auth is therefore deferred to Phase 13, which will introduce a
// dedicated header (e.g. X-Private-Token) on the spec.
func (h *Handler) DeleteScan(ctx context.Context, params client.DeleteScanParams) (client.DeleteScanRes, error) {
	id := params.GUID.String()
	if _, err := h.store.Get(ctx, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return errEnvelope(404, "not_found", "scan not found"), nil
		}
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	if err := h.store.Delete(ctx, id); err != nil {
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	return &client.DeleteScanNoContent{}, nil
}

// ListChecks implements GET /api/v1/checks.
func (h *Handler) ListChecks(_ context.Context) ([]client.Check, error) {
	if h.registry == nil {
		return []client.Check{}, nil
	}
	cat := h.registry.Catalog()
	out := make([]client.Check, 0, len(cat))
	for _, m := range cat {
		out = append(out, toClientCheck(m))
	}
	return out, nil
}

// GetCheck implements GET /api/v1/checks/{check_id}.
func (h *Handler) GetCheck(_ context.Context, params client.GetCheckParams) (client.GetCheckRes, error) {
	if h.registry == nil {
		return errEnvelope(404, "not_found", "check not found"), nil
	}
	c, ok := h.registry.Get(params.CheckID)
	if !ok {
		return errEnvelope(404, "not_found", "check not found"), nil
	}
	m := checks.CheckMeta{
		ID:              c.ID(),
		Family:          c.Family(),
		DefaultSeverity: c.DefaultSeverity(),
	}
	if d, ok := c.(checks.Describer); ok {
		m.Title = d.Title()
		m.Description = d.Description()
		m.RFCRefs = d.RFCRefs()
	}
	cc := toClientCheck(m)
	return &cc, nil
}

// waitForCompletion polls the store every 50 ms (capped by d) until the
// scan reaches a terminal state, then returns the freshest snapshot.
//
// Polling is preferred over Subscribe here because the scan may complete
// faster than the broker subscription can attach (very small registries,
// cached results, ...). Polling is race-free at the cost of up to 50 ms
// of latency.
func (h *Handler) waitForCompletion(id string, d time.Duration) *storage.Scan {
	deadline := time.Now().Add(d)
	for {
		scan, err := h.store.Get(context.Background(), id)
		if err != nil {
			return &storage.Scan{ID: id, Status: storage.StatusFailed, Error: err.Error()}
		}
		if scan.Status == storage.StatusCompleted || scan.Status == storage.StatusFailed {
			return scan
		}
		left := time.Until(deadline)
		if left <= 0 {
			return scan
		}
		sleep := 50 * time.Millisecond
		if left < sleep {
			sleep = left
		}
		time.Sleep(sleep)
	}
}

// toScanCreated builds the 202 response payload (always returns the
// ScanCreatedHeaders variant — ogen will write the headers + body).
func (h *Handler) toScanCreated(s *storage.Scan) *client.ScanCreatedHeaders {
	id, _ := uuid.Parse(s.ID)
	links := h.linksFor(s.ID)
	resp := client.ScanCreated{
		ID:     id,
		Status: client.ScanStatus(s.Status),
		Target: s.Target,
		Links:  links,
	}
	if s.PrivateToken != "" {
		resp.PrivateToken = client.NewOptString(s.PrivateToken)
	}
	return &client.ScanCreatedHeaders{
		Location:   client.NewOptString(links.Self),
		RetryAfter: client.NewOptInt(5),
		Response:   resp,
	}
}

// toClientScan converts a stored Scan into the public schema.
func (h *Handler) toClientScan(s *storage.Scan) *client.Scan {
	id, _ := uuid.Parse(s.ID)
	out := &client.Scan{
		ID:        id,
		Status:    client.ScanStatus(s.Status),
		Target:    s.Target,
		StartedAt: s.StartedAt,
		Links:     h.linksFor(s.ID),
	}
	if s.CompletedAt != nil {
		out.CompletedAt = client.NewOptDateTime(*s.CompletedAt)
	}
	if s.Progress.Total > 0 || s.Progress.Completed > 0 {
		p := client.Progress{
			Total:     s.Progress.Total,
			Completed: s.Progress.Completed,
		}
		if s.Progress.CurrentPhase != "" {
			p.CurrentPhase = client.NewOptString(s.Progress.CurrentPhase)
		}
		out.Progress = client.NewOptProgress(p)
	}
	if len(s.Findings) > 0 {
		out.Findings = make([]client.Finding, 0, len(s.Findings))
		for _, f := range s.Findings {
			out.Findings = append(out.Findings, toClientFinding(f))
		}
	}
	if s.Error != "" {
		out.Error = client.NewOptString(s.Error)
	}
	return out
}

func (h *Handler) linksFor(id string) client.ScanLinks {
	base := "/api/v1/scans/" + id
	return client.ScanLinks{
		Self:     base,
		Events:   client.NewOptString(base + "/events"),
		Markdown: client.NewOptString(base + "/markdown"),
		Sarif:    client.NewOptString(base + "/sarif"),
	}
}

func toClientCheck(m checks.CheckMeta) client.Check {
	c := client.Check{
		ID:              m.ID,
		Family:          string(m.Family),
		DefaultSeverity: client.Severity(m.DefaultSeverity),
		RfcRefs:         append([]string(nil), m.RFCRefs...),
	}
	if m.Title != "" {
		c.Title = client.NewOptString(m.Title)
	}
	if m.Description != "" {
		c.Description = client.NewOptString(m.Description)
	}
	return c
}

func toClientFinding(f checks.Finding) client.Finding {
	out := client.Finding{
		ID:       f.ID,
		Family:   string(f.Family),
		Severity: client.Severity(f.Severity),
		Status:   client.FindingStatus(f.Status),
	}
	if f.Title != "" {
		out.Title = client.NewOptString(f.Title)
	}
	if f.Description != "" {
		out.Description = client.NewOptString(f.Description)
	}
	if len(f.Evidence) > 0 {
		ev := make(client.FindingEvidence, len(f.Evidence))
		for k, v := range f.Evidence {
			ev[k] = jx.Raw(jsonRaw(v))
		}
		out.Evidence = client.NewOptFindingEvidence(ev)
	}
	if len(f.Remediation) > 0 {
		rm := make(client.FindingRemediation, len(f.Remediation))
		for k, v := range f.Remediation {
			rm[k] = jx.Raw(jsonRaw(v))
		}
		out.Remediation = client.NewOptFindingRemediation(rm)
	}
	return out
}

func jsonRaw(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}

func errEnvelope(status int, code, message string) *client.ErrorStatusCode {
	return &client.ErrorStatusCode{
		StatusCode: status,
		Response: client.Error{
			Code:    code,
			Message: message,
		},
	}
}
