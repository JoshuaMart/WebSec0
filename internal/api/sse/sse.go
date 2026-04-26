// Package sse provides a small, dependency-free helper for writing
// Server-Sent Events that follows the WHATWG `text/event-stream` spec.
//
// SPECIFICATIONS.md §5.6: events carry an `id` for `Last-Event-ID`
// reconnect, a `retry` hint, and we emit a periodic comment heartbeat
// (`:keepalive\n\n`) to keep idle proxies open.
package sse

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Writer represents a single SSE connection. Use New() to construct one.
type Writer struct {
	w       http.ResponseWriter
	flusher http.Flusher
	id      uint64
}

// New writes the standard SSE response headers and returns a Writer. It
// returns an error if the underlying ResponseWriter does not support
// flushing (e.g. when used behind an http.ResponseRecorder).
func New(w http.ResponseWriter) (*Writer, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("sse: ResponseWriter does not implement Flusher")
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return &Writer{w: w, flusher: flusher}, nil
}

// SetRetry instructs the browser EventSource to wait at least d before
// reconnecting after a drop. Sent as `retry: <ms>`.
func (s *Writer) SetRetry(d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if _, err := fmt.Fprintf(s.w, "retry: %d\n\n", d.Milliseconds()); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

// Heartbeat writes a comment line so intermediaries don't time out.
func (s *Writer) Heartbeat() error {
	if _, err := fmt.Fprint(s.w, ":keepalive\n\n"); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

// Send emits a structured event. eventName may be empty (default
// "message"). data is written verbatim — the caller marshals JSON.
func (s *Writer) Send(eventName string, data []byte) error {
	s.id++
	var sb strings.Builder
	if eventName != "" {
		sb.WriteString("event: ")
		sb.WriteString(eventName)
		sb.WriteByte('\n')
	}
	sb.WriteString("id: ")
	sb.WriteString(strconv.FormatUint(s.id, 10))
	sb.WriteByte('\n')
	for _, line := range strings.Split(string(data), "\n") {
		sb.WriteString("data: ")
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteByte('\n')
	if _, err := s.w.Write([]byte(sb.String())); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

// LastEventID returns the value of the Last-Event-ID header, or empty.
func LastEventID(r *http.Request) string {
	return r.Header.Get("Last-Event-ID")
}

// HeartbeatLoop emits a heartbeat every interval until ctx is cancelled or
// the writer fails. Run it from a goroutine alongside your event pump.
func (s *Writer) HeartbeatLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Heartbeat(); err != nil {
				return
			}
		}
	}
}
