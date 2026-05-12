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
