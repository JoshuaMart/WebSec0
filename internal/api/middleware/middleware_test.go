package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

// --- RequestID --------------------------------------------------------

func TestRequestID_GeneratesAndPropagates(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	h.ServeHTTP(rec, req)

	if seen == "" {
		t.Error("RequestID did not propagate to handler context")
	}
	if got := rec.Header().Get("X-Request-ID"); got != seen {
		t.Errorf("response X-Request-ID = %q, want %q", got, seen)
	}
	if len(seen) != 32 {
		t.Errorf("generated id length = %d, want 32 (16-byte hex)", len(seen))
	}
}

func TestRequestID_HonoursValidClientID(t *testing.T) {
	const clientID = "trace-abc_123"
	var seen string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", clientID)
	h.ServeHTTP(rec, req)
	if seen != clientID {
		t.Errorf("seen = %q, want %q", seen, clientID)
	}
}

func TestRequestID_RejectsInvalidClientID(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))

	for name, badID := range map[string]string{
		"contains space":  "bad id",
		"contains slash":  "bad/id",
		"too long":        strings.Repeat("a", 65),
		"empty":           "",
		"contains period": "bad.id",
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Request-ID", badID)
			h.ServeHTTP(rec, req)
			if seen == badID {
				t.Errorf("badID %q should have been replaced, got passthrough", badID)
			}
			if len(seen) != 32 {
				t.Errorf("expected fresh 32-hex id, got %q", seen)
			}
		})
	}
}

func TestRequestIDFromContext_NoMiddleware(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("RequestIDFromContext on empty ctx = %q, want \"\"", got)
	}
}

// --- SourceIP ---------------------------------------------------------

func TestSourceIP_FromXForwardedFor(t *testing.T) {
	var ip string
	h := SourceIP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ip = SourceIPFromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	req.RemoteAddr = "10.0.0.1:5555"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if ip != "203.0.113.5" {
		t.Errorf("SourceIP = %q, want 203.0.113.5", ip)
	}
}

func TestSourceIP_FromRemoteAddr(t *testing.T) {
	var ip string
	h := SourceIP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ip = SourceIPFromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:443"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if ip != "192.0.2.1" {
		t.Errorf("SourceIP = %q, want 192.0.2.1", ip)
	}
}

func TestSourceIPFromContext_NoMiddleware(t *testing.T) {
	if got := SourceIPFromContext(context.Background()); got != "" {
		t.Errorf("SourceIPFromContext on empty ctx = %q, want \"\"", got)
	}
}

// --- Recover ----------------------------------------------------------

func TestRecover_PanicProduces500(t *testing.T) {
	mw := Recover(discardLogger())
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal_error") {
		t.Errorf("body = %q, want to contain internal_error", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

func TestRecover_NoPanicPassesThrough(t *testing.T) {
	mw := Recover(discardLogger())
	h := mw(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want ok", rec.Body.String())
	}
}

// --- AccessLog --------------------------------------------------------

func TestAccessLog_LogsAndPassesThrough(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	mw := AccessLog(log, false)
	h := mw(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/foo?x=1", nil)
	h.ServeHTTP(rec, req)
	out := buf.String()
	for _, want := range []string{`"method":"GET"`, `"path":"/foo"`, `"status":200`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s\n--- log ---\n%s", want, out)
		}
	}
	// logTargets=false → query must NOT appear.
	if strings.Contains(out, "x=1") {
		t.Errorf("query leaked despite logTargets=false:\n%s", out)
	}
}

func TestAccessLog_LogTargetsIncludesQuery(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	mw := AccessLog(log, true)
	h := mw(okHandler())
	req := httptest.NewRequest("GET", "/scan?refresh=true", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(buf.String(), `"query":"refresh=true"`) {
		t.Errorf("expected query in log, got:\n%s", buf.String())
	}
}

// --- CORS -------------------------------------------------------------

func TestCORS_DefaultOrigins(t *testing.T) {
	mw := CORS(CORSOptions{})
	h := mw(okHandler())
	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// chi/cors lets the preflight through with 200/204 and sets headers.
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Errorf("expected Access-Control-Allow-Origin to be set, headers: %v", rec.Header())
	}
}

func TestCORS_ExplicitAllowlist(t *testing.T) {
	mw := CORS(CORSOptions{AllowedOrigins: []string{"https://allowed.example.com"}})
	h := mw(okHandler())

	allow := httptest.NewRecorder()
	r1 := httptest.NewRequest("OPTIONS", "/", nil)
	r1.Header.Set("Origin", "https://allowed.example.com")
	r1.Header.Set("Access-Control-Request-Method", "GET")
	h.ServeHTTP(allow, r1)
	if got := allow.Header().Get("Access-Control-Allow-Origin"); got != "https://allowed.example.com" {
		t.Errorf("allowed origin not echoed, got %q", got)
	}

	deny := httptest.NewRecorder()
	r2 := httptest.NewRequest("OPTIONS", "/", nil)
	r2.Header.Set("Origin", "https://other.example.com")
	r2.Header.Set("Access-Control-Request-Method", "GET")
	h.ServeHTTP(deny, r2)
	if got := deny.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin should not be echoed, got %q", got)
	}
}

// --- JoinOriginList ---------------------------------------------------

func TestJoinOriginList(t *testing.T) {
	cases := map[string][]string{
		"":                    nil,
		"   ":                 nil,
		"a":                   {"a"},
		"a,b":                 {"a", "b"},
		" a , b , ":           {"a", "b"},
		"https://x.example,*": {"https://x.example", "*"},
	}
	for in, want := range cases {
		got := JoinOriginList(in)
		if len(got) != len(want) {
			t.Errorf("JoinOriginList(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("JoinOriginList(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}
