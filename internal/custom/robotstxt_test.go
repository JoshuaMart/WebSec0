package custom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestFindSuspiciousDisallows(t *testing.T) {
	body := `User-agent: *
Disallow: /admin
Disallow: /admin/users
Disallow: /api/v1
Disallow: /public
Disallow: /
Disallow:    # blank
Disallow: /admin   # duplicate, deduped
`
	got := findSuspiciousDisallows(body)
	want := []string{"/admin", "/admin/users", "/api/v1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFindSuspiciousDisallows_MatchesAllListedPrefixes(t *testing.T) {
	for _, prefix := range suspiciousPathPrefixes {
		body := "Disallow: " + prefix + "/foo\n"
		got := findSuspiciousDisallows(body)
		if len(got) != 1 {
			t.Errorf("prefix %s: got %d matches, want 1", prefix, len(got))
		}
	}
}

func TestFindSuspiciousDisallows_IgnoresComments(t *testing.T) {
	body := `# Disallow: /admin    -- this is a comment
Disallow: /public
`
	got := findSuspiciousDisallows(body)
	if len(got) != 0 {
		t.Errorf("expected no matches (comment + public), got %v", got)
	}
}

func TestRobotsTxt_Pass_CleanFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /search\n"))
	}))
	defer srv.Close()
	f := RobotsTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusPass {
		t.Errorf("clean file: got %s, want pass", f.Status)
	}
	var d robotsTxtDetails
	_ = json.Unmarshal(f.Details, &d)
	if len(d.SuspiciousDisallow) != 0 {
		t.Errorf("clean file should have no suspicious entries, got %v", d.SuspiciousDisallow)
	}
}

func TestRobotsTxt_Warn_SuspiciousDisallows(t *testing.T) {
	body := "User-agent: *\nDisallow: /admin\nDisallow: /.git\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f := RobotsTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusWarn {
		t.Errorf("suspicious file: got %s, want warn", f.Status)
	}
	var d robotsTxtDetails
	_ = json.Unmarshal(f.Details, &d)
	if len(d.SuspiciousDisallow) != 2 {
		t.Errorf("expected 2 suspicious entries, got %v", d.SuspiciousDisallow)
	}
}

func TestRobotsTxt_Info_Missing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	f := RobotsTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusInfo {
		t.Errorf("404: got %s, want info", f.Status)
	}
}

// TestRobotsTxt_Info_HTMLContentType ensures that a 200 response served
// as text/html (typical SPA fallback) is reported as not-parseable,
// regardless of body content. The signal is the response media type,
// not body sniffing.
func TestRobotsTxt_Info_HTMLContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>landing</body></html>"))
	}))
	defer srv.Close()
	f := RobotsTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusInfo {
		t.Errorf("HTML response: got %s, want info", f.Status)
	}
	var d robotsTxtDetails
	_ = json.Unmarshal(f.Details, &d)
	if d.Parseable {
		t.Errorf("HTML response must not be parseable, got %+v", d)
	}
	if d.Note == "" {
		t.Errorf("HTML response should set a Note, got empty")
	}
}

// TestRobotsTxt_Pass_NoContentType accepts a server that returns plain
// text without a Content-Type header — we don't have evidence it's HTML,
// so the parser runs as usual.
func TestRobotsTxt_Pass_NoContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Go's http.ResponseWriter auto-sniffs the Content-Type from the
		// body when not set. Disable that by overriding to empty.
		w.Header()["Content-Type"] = nil
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /tmp/\n"))
	}))
	defer srv.Close()
	f := RobotsTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusPass {
		t.Errorf("no Content-Type but plain body: got %s, want pass", f.Status)
	}
}
