package frontend

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
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
	_, err := Handler("")
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
	h, err := Handler("")
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

func TestHandler_SPAFallback(t *testing.T) {
	sub, _ := FS()
	if _, err := fs.Stat(sub, indexPath); err != nil {
		t.Skip("frontend dist not built — run `make frontend` first")
	}
	h, err := Handler("")
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
	h, err := Handler(snippet)
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
	h, err := Handler("")
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
	h, err := Handler("")
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
