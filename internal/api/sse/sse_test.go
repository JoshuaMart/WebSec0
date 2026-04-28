package sse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// flushRecorder wraps httptest.ResponseRecorder with a no-op Flush so
// the SSE Writer accepts it.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (f *flushRecorder) Flush() { f.flushes++ }

func TestNew_SetsHeadersAndFlushes(t *testing.T) {
	rec := newFlushRecorder()
	w, err := New(rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if w == nil {
		t.Fatal("New returned nil writer")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Errorf("Cache-Control = %q, want no-cache,…", got)
	}
	if got := rec.Header().Get("X-Accel-Buffering"); got != "no" {
		t.Errorf("X-Accel-Buffering = %q, want no", got)
	}
	if rec.flushes < 1 {
		t.Error("New did not flush after writing headers")
	}
}

// fakeWriter satisfies http.ResponseWriter but not http.Flusher.
type fakeWriter struct {
	h http.Header
}

func (f *fakeWriter) Header() http.Header         { return f.h }
func (f *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeWriter) WriteHeader(int)             {}

func TestNew_RejectsNonFlusher(t *testing.T) {
	w := &fakeWriter{h: http.Header{}}
	if _, err := New(w); err == nil {
		t.Error("expected error when ResponseWriter does not implement Flusher")
	}
}

func TestSend_FormatsEvent(t *testing.T) {
	rec := newFlushRecorder()
	w, err := New(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Send("progress", []byte(`{"completed":1}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := rec.Body.String()
	wantLines := []string{
		"event: progress",
		"id: 1",
		`data: {"completed":1}`,
		"",
	}
	for _, line := range wantLines {
		if !strings.Contains(body, line+"\n") && !strings.HasSuffix(body, line) {
			t.Errorf("body missing %q\n--- body ---\n%s", line, body)
		}
	}
}

func TestSend_MultilineDataSplit(t *testing.T) {
	rec := newFlushRecorder()
	w, _ := New(rec)
	if err := w.Send("", []byte("line1\nline2\nline3")); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	for _, line := range []string{"data: line1", "data: line2", "data: line3"} {
		if !strings.Contains(body, line) {
			t.Errorf("body missing %q\n%s", line, body)
		}
	}
	// No "event:" line when eventName is empty.
	if strings.Contains(body, "event: ") {
		t.Errorf("unexpected event header for empty name:\n%s", body)
	}
}

func TestSend_IncrementsID(t *testing.T) {
	rec := newFlushRecorder()
	w, _ := New(rec)
	for i := 0; i < 3; i++ {
		_ = w.Send("e", []byte("d"))
	}
	body := rec.Body.String()
	for _, want := range []string{"id: 1", "id: 2", "id: 3"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n%s", want, body)
		}
	}
}

func TestSetRetry(t *testing.T) {
	rec := newFlushRecorder()
	w, _ := New(rec)
	if err := w.SetRetry(2500 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), "retry: 2500\n") {
		t.Errorf("missing retry: 2500\n%s", rec.Body.String())
	}
}

func TestSetRetry_ZeroIsNoop(t *testing.T) {
	rec := newFlushRecorder()
	w, _ := New(rec)
	pre := rec.Body.Len()
	if err := w.SetRetry(0); err != nil {
		t.Fatal(err)
	}
	if rec.Body.Len() != pre {
		t.Errorf("zero retry wrote %d bytes, want 0", rec.Body.Len()-pre)
	}
}

func TestHeartbeat(t *testing.T) {
	rec := newFlushRecorder()
	w, _ := New(rec)
	if err := w.Heartbeat(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), ":keepalive\n\n") {
		t.Errorf("missing keepalive comment\n%s", rec.Body.String())
	}
}

func TestHeartbeatLoop_StopsOnContextCancel(t *testing.T) {
	rec := newFlushRecorder()
	w, _ := New(rec)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.HeartbeatLoop(ctx, 5*time.Millisecond)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("HeartbeatLoop did not exit within 200ms of cancel")
	}
	if !strings.Contains(rec.Body.String(), ":keepalive") {
		t.Errorf("expected at least one keepalive in body:\n%s", rec.Body.String())
	}
}

func TestHeartbeatLoop_ZeroIntervalReturns(t *testing.T) {
	rec := newFlushRecorder()
	w, _ := New(rec)
	done := make(chan struct{})
	go func() {
		w.HeartbeatLoop(context.Background(), 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("HeartbeatLoop with zero interval did not return")
	}
}

func TestLastEventID(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Last-Event-ID", "42")
	if got := LastEventID(r); got != "42" {
		t.Errorf("LastEventID = %q, want 42", got)
	}
}
