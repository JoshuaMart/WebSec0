// Package frontend embeds the Astro static build and exposes it as an
// http.Handler with SPA fallback. The dist directory is populated by
// `make frontend` (see Makefile) which copies web/dist into here.
//
// A .keep file ships with the repository so the //go:embed directive
// never fails on a fresh clone, but the served content is only useful
// after the frontend has been built.
package frontend

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

//go:embed all:dist
var rawFS embed.FS

// indexPath is the SPA entry point; every unknown URL not under /r/ falls
// back to it. reportIndexPath is the dedicated shell for the report
// pages so /r/<scan-id> mounts the Report island rather than the landing.
const (
	indexPath       = "index.html"
	reportIndexPath = "r/index.html"
)

// FS returns the embedded filesystem rooted at the build output.
func FS() (fs.FS, error) {
	return fs.Sub(rawFS, "dist")
}

// ErrIndexMissing is returned by Handler when the dist directory does not
// contain an index.html — typically because `make frontend` has not run
// yet on this checkout.
var ErrIndexMissing = errors.New("frontend: index.html missing — run `make frontend`")

// Handler returns an http.Handler that serves the embedded frontend with
// SPA fallback: any URL that does not correspond to an existing file is
// answered with the contents of index.html so the client-side router
// (Astro + Preact) can take over (e.g. /r/<scan-id>).
//
// The fallback writes the index bytes directly rather than rewriting the
// request and re-entering http.FileServer, which would trigger Go's
// built-in `/index.html → ./` redirect and loop.
//
// When the embedded dist does not contain index.html, Handler returns
// ErrIndexMissing so callers can choose to disable the frontend route
// gracefully rather than panic.
//
// headInject, when non-empty, is spliced once into every shell HTML just
// before </head>. Used to opt the public deployment into analytics
// without touching self-hosted builds. The snippet is trusted operator
// config — not escaped. If </head> is absent (or the snippet is empty)
// the bytes are served verbatim.
//
// staticOverlayDir, when non-empty, is a directory whose tree mirrors
// URL paths. Anything under .well-known/ is served from the overlay
// when the file exists; at the root only a closed whitelist (robots.txt,
// humans.txt, ads.txt, sitemap.xml) is honoured so a misconfigured
// overlay cannot accidentally hijack index.html or the report shell.
// Paths absent from the overlay fall back to the embedded fs.
func Handler(headInject, staticOverlayDir string) (http.Handler, error) {
	sub, err := FS()
	if err != nil {
		return nil, err
	}
	indexBytes, err := fs.ReadFile(sub, indexPath)
	if err != nil {
		return nil, ErrIndexMissing
	}
	indexBytes = injectHead(indexBytes, headInject)
	// The report shell is optional — if it has not been built yet, /r/* paths
	// fall back to the landing.
	reportBytes, _ := fs.ReadFile(sub, reportIndexPath)
	if reportBytes != nil {
		reportBytes = injectHead(reportBytes, headInject)
	}
	server := http.FileServer(http.FS(sub))

	var (
		overlay       http.Handler
		overlayAbsDir string
	)
	if staticOverlayDir != "" {
		abs, absErr := filepath.Abs(staticOverlayDir)
		if absErr != nil {
			return nil, fmt.Errorf("frontend: static_overlay_dir: %w", absErr)
		}
		overlayAbsDir = abs
		// http.Dir already rejects ".." and absolute paths in the URL; we
		// add an explicit "stays under the overlay dir" check below as
		// belt-and-suspenders defence and to keep static analyzers happy.
		overlay = http.FileServer(http.Dir(staticOverlayDir))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if rel == "" || rel == indexPath {
			writeIndex(w, indexBytes)
			return
		}
		// Overlay wins when configured AND the path is allowed AND the
		// resolved file stays inside the overlay tree AND the file
		// exists on disk; otherwise fall through to the embedded fs so
		// an upstream-shipped file is still served.
		if overlay != nil && overlayAllowed(rel) {
			joined := filepath.Join(overlayAbsDir, rel)
			if joined == overlayAbsDir ||
				strings.HasPrefix(joined, overlayAbsDir+string(filepath.Separator)) {
				if info, err := os.Stat(joined); err == nil && !info.IsDir() {
					overlay.ServeHTTP(w, r)
					return
				}
			}
		}
		if info, err := fs.Stat(sub, rel); err == nil && !info.IsDir() {
			server.ServeHTTP(w, r)
			return
		}
		// SPA fallback — pick the right shell based on path prefix.
		if reportBytes != nil && strings.HasPrefix(rel, "r/") {
			writeIndex(w, reportBytes)
			return
		}
		writeIndex(w, indexBytes)
	}), nil
}

// staticRootOverlayAllowed is the closed set of root-level files an
// operator may override via the static overlay. Embedded SPA artefacts
// (index.html, the report shell, hashed Astro assets) are deliberately
// excluded so a misconfigured overlay can't break the UI.
var staticRootOverlayAllowed = map[string]bool{
	"robots.txt":  true,
	"humans.txt":  true,
	"ads.txt":     true,
	"sitemap.xml": true,
}

// overlayAllowed returns true when rel may be served from the overlay
// directory. Anything under .well-known/ is always allowed; at the root
// the whitelist applies.
func overlayAllowed(rel string) bool {
	if strings.HasPrefix(rel, ".well-known/") {
		return true
	}
	return staticRootOverlayAllowed[rel]
}

// injectHead splices snippet just before the first </head> in body.
// Returns body unchanged when snippet is empty or no </head> marker is
// found, so a malformed shell still ships rather than panicking.
func injectHead(body []byte, snippet string) []byte {
	if snippet == "" {
		return body
	}
	marker := []byte("</head>")
	i := bytes.Index(body, marker)
	if i < 0 {
		return body
	}
	out := make([]byte, 0, len(body)+len(snippet))
	out = append(out, body[:i]...)
	out = append(out, snippet...)
	out = append(out, body[i:]...)
	return out
}

func writeIndex(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
