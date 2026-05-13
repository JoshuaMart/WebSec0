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

// TestRobotsTxt_Info_HTMLFallback ensures we don't mark an SPA's
// landing-page HTML as a parseable robots.txt just because the server
// answered 200 on /robots.txt.
func TestRobotsTxt_Info_HTMLFallback(t *testing.T) {
	html := "<!doctype html><html><head><title>landing</title></head><body>…</body></html>"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(html))
	}))
	defer srv.Close()
	f := RobotsTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusInfo {
		t.Errorf("HTML body: got %s, want info", f.Status)
	}
	var d robotsTxtDetails
	_ = json.Unmarshal(f.Details, &d)
	if d.Parseable {
		t.Errorf("HTML body must not be marked parseable, got %+v", d)
	}
	if d.Note == "" {
		t.Errorf("HTML body should set a Note explaining the situation, got empty")
	}
}

func TestLooksLikeRobotsTxt(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", true},
		{"whitespace only", "  \n\t \n", true},
		{"plain robots", "User-agent: *\nDisallow: /admin\n", true},
		{"comments only", "# this is a comment\n# another\n", true},
		{"html doctype", "<!doctype html><html>…", false},
		{"html start tag", "<html><body>oops</body></html>", false},
		{"html with leading whitespace", "   <html>oops</html>", false},
		{"closing body tag mid-body", "User-agent: *\n</body>\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeRobotsTxt(c.body); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
