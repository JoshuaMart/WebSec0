package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-faster/jx"

	"github.com/Jomar/websec101/internal/report"
	"github.com/Jomar/websec101/internal/storage"
	client "github.com/Jomar/websec101/pkg/client"
)

// GetScanMarkdown implements GET /api/v1/scans/{guid}/markdown.
func (h *Handler) GetScanMarkdown(ctx context.Context, params client.GetScanMarkdownParams) (client.GetScanMarkdownRes, error) {
	scan, err := h.store.Get(ctx, params.GUID.String())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return errEnvelope(404, "not_found", "scan not found"), nil
		}
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	rep, ok := scan.Report.(*report.Report)
	if !ok || rep == nil {
		if scan.Status == storage.StatusFailed {
			return errEnvelope(409, "scan_failed", scan.Error), nil
		}
		return errEnvelope(409, "scan_not_completed", "report is not yet available"), nil
	}
	md := report.Markdown(rep)
	return &client.GetScanMarkdownOK{Data: strings.NewReader(md)}, nil
}

// GetScanSARIF implements GET /api/v1/scans/{guid}/sarif.
func (h *Handler) GetScanSARIF(ctx context.Context, params client.GetScanSARIFParams) (client.GetScanSARIFRes, error) {
	scan, err := h.store.Get(ctx, params.GUID.String())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return errEnvelope(404, "not_found", "scan not found"), nil
		}
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	rep, ok := scan.Report.(*report.Report)
	if !ok || rep == nil {
		if scan.Status == storage.StatusFailed {
			return errEnvelope(409, "scan_failed", scan.Error), nil
		}
		return errEnvelope(409, "scan_not_completed", "report is not yet available"), nil
	}
	doc := report.ToSARIF(rep)
	// Convert to map[string]jx.Raw via JSON round-trip — ogen's
	// GetScanSARIFOK is a free-form object, so we serialize the typed
	// SARIF struct and re-decode into the wire shape it expects.
	raw, err := json.Marshal(doc)
	if err != nil {
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return errEnvelope(500, "internal_error", err.Error()), nil
	}
	out := make(client.GetScanSARIFOK, len(generic))
	for k, v := range generic {
		out[k] = jx.Raw(v)
	}
	return &out, nil
}
