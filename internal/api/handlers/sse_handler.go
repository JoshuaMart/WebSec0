package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/JoshuaMart/websec0/internal/api/sse"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/JoshuaMart/websec0/internal/storage"
)

// heartbeatInterval is how often the SSE connection emits a comment line
// to keep idle proxies (nginx, ALB, ...) from closing the stream.
const heartbeatInterval = 15 * time.Second

// SSEHandler returns an http.HandlerFunc that streams scan events for the
// scan id taken from chi URL param "guid". It honours the spec contract:
// progress, finding, completed/failed events; retry hint; heartbeat.
//
// Behaviour by current state:
//   - unknown id          → 404 JSON
//   - already terminal    → emit one synthetic completed/failed event from
//     the stored Scan and close
//   - in flight           → live-subscribe via the manager, stream until
//     a terminal event arrives or the client drops
func (h *Handler) SSEHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "guid")
	if id == "" {
		writeJSONErr(w, http.StatusBadRequest, "bad_request", "missing guid")
		return
	}

	scan, err := h.store.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSONErr(w, http.StatusNotFound, "not_found", "scan not found")
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	stream, err := sse.New(w)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "sse_unsupported", err.Error())
		return
	}
	_ = stream.SetRetry(3 * time.Second)

	if scan.Status == storage.StatusCompleted || scan.Status == storage.StatusFailed {
		emitTerminalFromStore(stream, scan)
		return
	}

	if h.scans == nil {
		writeJSONErr(w, http.StatusInternalServerError, "scans_not_wired", "manager unavailable")
		return
	}

	ch, cancel, err := h.scans.Subscribe(id)
	if err != nil {
		// Race: scan finished between Get and Subscribe. Re-read store.
		fresh, gerr := h.store.Get(r.Context(), id)
		if gerr == nil {
			emitTerminalFromStore(stream, fresh)
		}
		return
	}
	defer cancel()

	hbCtx, hbCancel := context.WithCancel(r.Context())
	defer hbCancel()
	go stream.HeartbeatLoop(hbCtx, heartbeatInterval)

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				// broker closed without a terminal event — treat as completed
				_ = stream.Send(string(scanner.EventCompleted), []byte("{}"))
				return
			}
			if !sendEvent(stream, e) {
				return
			}
			if e.Kind == scanner.EventCompleted || e.Kind == scanner.EventFailed {
				return
			}
		}
	}
}

func sendEvent(stream *sse.Writer, e scanner.Event) bool {
	var payload any
	switch e.Kind {
	case scanner.EventProgress:
		payload = e.Progress
	case scanner.EventFinding:
		payload = e.Finding
	case scanner.EventCompleted:
		payload = map[string]any{"grade": e.Grade, "score": e.Score}
	case scanner.EventFailed:
		payload = map[string]any{"error": e.Error}
	default:
		return true
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	return stream.Send(string(e.Kind), b) == nil
}

func emitTerminalFromStore(stream *sse.Writer, scan *storage.Scan) {
	// Replay a single synthetic progress event so late subscribers
	// always see the trio progress / finding / completed.
	progress := scanner.Progress{
		Total:        scan.Progress.Total,
		Completed:    scan.Progress.Completed,
		CurrentPhase: scan.Progress.CurrentPhase,
	}
	if pb, err := json.Marshal(progress); err == nil {
		_ = stream.Send(string(scanner.EventProgress), pb)
	}
	for _, f := range scan.Findings {
		b, err := json.Marshal(f)
		if err != nil {
			continue
		}
		_ = stream.Send(string(scanner.EventFinding), b)
	}
	if scan.Status == storage.StatusFailed {
		b, _ := json.Marshal(map[string]any{"error": scan.Error})
		_ = stream.Send(string(scanner.EventFailed), b)
		return
	}
	_ = stream.Send(string(scanner.EventCompleted), []byte("{}"))
}

func writeJSONErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"code": code, "message": message})
	_, _ = w.Write(body)
}
