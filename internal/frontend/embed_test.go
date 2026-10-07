package frontend

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFS_HasAtLeastKeep guards against breaking the //go:embed directive.
// The repository ships internal/frontend/dist/.keep precisely so this
// test (and the embed) succeed on a fresh checkout.
func TestFS_HasAtLeastKeep(t *testing.T) {
	sub, err := FS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(sub, ".keep"); err != nil {
		t.Errorf(".keep should be embedded: %v", err)
	}
}

// TestHandler_NoIndexReturnsErrIndexMissing covers the "fresh clone"
// case: only .keep is present, Handler must refuse and let the caller
// decide what to do.
func TestHandler_NoIndexReturnsErrIndexMissing(t *testing.T) {
	if _, err := FS(); err != nil {
		t.Fatal(err)
	}
	// If index.html is present (i.e., `make frontend` was already run on
	// this checkout) we skip — the integration tests below cover that path.
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err == nil {
		t.Skip("frontend dist contains index.html — skipping the no-index path")
	}
	_, err := Handler("", "", nil)
	if !errors.Is(err, ErrIndexMissing) {
		t.Fatalf("expected ErrIndexMissing, got %v", err)
	}
}

// TestHandler_ServesIndex and TestHandler_SPAFallback both require an
// actual frontend build. They auto-skip on checkouts where the bundle
// has not been synced yet.
func TestHandler_ServesIndex(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	h, err := Handler("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "WebSec0") {
		t.Errorf("expected body to mention WebSec0, got %q", body)
	}
}

// Discovery files must survive the Astro build/embed pipeline and bypass the
// HTML fallback that previously made Lighthouse parse the landing page.
func TestHandler_AgentDiscovery(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	h, err := Handler("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		mime string
	}{
		{"/llms.txt", "text/plain"},
		{"/.well-known/ai-catalog.json", "application/json"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))
			if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), tc.mime) {
				t.Fatalf("status=%d content-type=%q, want 200 %s", w.Code, w.Header().Get("Content-Type"), tc.mime)
			}
			if tc.mime == "application/json" {
				if !json.Valid(w.Body.Bytes()) {
					t.Fatal("catalog response is not valid JSON")
				}
			} else if body := w.Body.String(); !strings.HasPrefix(body, "# WebSec0\n") || !strings.Contains(body, "](https://") {
				t.Fatal("llms.txt must contain a Markdown H1 and documentation links")
			}
		})
	}
}

func TestHandler_SPAFallback(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	h, err := Handler("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/r/some-scan-id")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 (SPA fallback should serve index.html)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "WebSec0") {
		t.Errorf("SPA fallback should serve index.html, got %q", body)
	}
}

func TestInjectHead(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		snippet string
		want    string
	}{
		{
			name:    "empty snippet returns body verbatim",
			body:    "<html><head><title>x</title></head><body>y</body></html>",
			snippet: "",
			want:    "<html><head><title>x</title></head><body>y</body></html>",
		},
		{
			name:    "splices before first </head>",
			body:    "<html><head><title>x</title></head><body>y</body></html>",
			snippet: "<script>z</script>",
			want:    "<html><head><title>x</title><script>z</script></head><body>y</body></html>",
		},
		{
			name:    "no </head> marker returns body verbatim",
			body:    "<html><body>no head here</body></html>",
			snippet: "<script>z</script>",
			want:    "<html><body>no head here</body></html>",
		},
		{
			name:    "multi-line snippet is preserved",
			body:    "<head></head>",
			snippet: "<script>\n  a\n  b\n</script>",
			want:    "<head><script>\n  a\n  b\n</script></head>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(injectHead([]byte(tc.body), tc.snippet))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHandler_InjectsSnippetInBothShells(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	const snippet = `<script data-test="websec0-inject"></script>`
	h, err := Handler(snippet, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{"/", "/r/some-scan-id"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		count := strings.Count(string(body), snippet)
		if count != 1 {
			t.Errorf("GET %s: snippet appeared %d times, want exactly 1", path, count)
		}
		if !strings.Contains(string(body), snippet+"</head>") {
			t.Errorf("GET %s: snippet should sit immediately before </head>", path)
		}
	}
}

func TestHandler_EmptyInjectKeepsBodyVerbatim(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	rawIndex, err := fs.ReadFile(sub, indexPath)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Handler("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, rawIndex) {
		t.Error("empty headInject should serve embedded index.html unchanged")
	}
}

func TestHandler_404ForMissingAsset(t *testing.T) {
	// SPA fallback rewrites ANY non-file path to /index.html. To verify
	// the rewrite happens (and we don't accidentally 404 on the rewritten
	// path), we ask for a deep unknown route and confirm we get 200.
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	h, err := Handler("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/totally/unknown/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200 (SPA fallback)", resp.StatusCode)
	}
}

// TestHandler_StaticOverlay verifies that:
//   - .well-known/* files inside the overlay dir are served from disk;
//   - root-level whitelisted files (robots.txt, humans.txt, …) are
//     served from disk;
//   - non-whitelisted root files in the overlay are IGNORED (no UI
//     hijack via index.html);
//   - paths absent from the overlay fall back to the embedded fs / SPA.
func TestHandler_StaticOverlay(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}

	dir := t.TempDir()
	// security.txt under .well-known/
	securityTxt := "Contact: https://example.test/sec\nExpires: 2099-01-01T00:00:00Z\n"
	if err := os.MkdirAll(filepath.Join(dir, ".well-known"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".well-known", "security.txt"), []byte(securityTxt), 0o644); err != nil {
		t.Fatal(err)
	}
	// robots.txt at the root.
	robots := "User-agent: *\nDisallow: /private/\n"
	if err := os.WriteFile(filepath.Join(dir, "robots.txt"), []byte(robots), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-whitelisted root file — must NOT be served from the overlay.
	hijack := "<html>HIJACKED</html>"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(hijack), 0o644); err != nil {
		t.Fatal(err)
	}

	h, err := Handler("", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	// 1) .well-known/security.txt → overlay.
	resp, err := http.Get(srv.URL + "/.well-known/security.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != securityTxt {
		t.Errorf(".well-known/security.txt: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 2) /robots.txt → overlay.
	resp, err = http.Get(srv.URL + "/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != robots {
		t.Errorf("/robots.txt: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 3) /index.html — overlay file is NOT served (would hijack the SPA).
	// Either the embedded SPA shell is served, or the SPA fallback kicks
	// in. Either way the response must NOT contain the hijack marker.
	resp, err = http.Get(srv.URL + "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(body, []byte("HIJACKED")) {
		t.Errorf("/index.html: overlay must not override the SPA shell, got hijacked content")
	}

	// 4) Overlay miss — .well-known path not on disk falls through to SPA.
	resp, err = http.Get(srv.URL + "/.well-known/missing.txt")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("overlay miss: status %d, want 200 (SPA fallback)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("overlay miss: content-type %q, want text/html…", ct)
	}
}

// TestHandler_ShellCSPAllowsItsInlineCode checks, on the real build, that each
// shell's policy lists a hash for every inline script it serves, including
// the head_inject snippet.
func TestHandler_ShellCSPAllowsItsInlineCode(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	const snippet = `<script>window.injected = 1</script>`
	h, err := Handler(snippet, "", []string{"https://stats.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{"/", "/r/some-scan-id", "/favicon.svg"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "https://stats.example.com") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("GET %s: unexpected policy %q", path, csp)
		}
		scripts, styles := inlineHashes(body)
		for _, h := range append(scripts, styles...) {
			if !strings.Contains(csp, h) {
				t.Errorf("GET %s: inline element hash %s missing from %q", path, h, csp)
			}
		}
		if path != "/favicon.svg" && !strings.Contains(csp, sha("window.injected = 1")) {
			t.Errorf("GET %s: head_inject script not hashed", path)
		}
	}
}
