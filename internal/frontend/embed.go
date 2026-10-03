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

// Handler serves embedded assets and the landing/report shells, or returns
// ErrIndexMissing if the frontend has not been built. Shells receive the
// trusted headInject HTML; allowed static files may come from staticOverlayDir.
// Shell bytes are written directly to avoid FileServer's index.html redirect.
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

	var overlay http.Handler
	if staticOverlayDir != "" {
		// http.Dir already rejects ".." and absolute paths in the URL;
		// the per-request filepath.IsLocal check below is the
		// documented (and CodeQL-recognised) sanitiser for path-
		// traversal, so the os.Stat call cannot escape the overlay.
		overlay = http.FileServer(http.Dir(staticOverlayDir))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if rel == "" || rel == indexPath {
			writeIndex(w, indexBytes)
			return
		}
		// Overlay wins when configured AND the path is allowed AND it
		// stays local to the overlay tree (filepath.IsLocal rejects
		// absolute paths, "..", and Windows volume references) AND the
		// file exists on disk. Otherwise fall through to the embedded
		// fs so an upstream-shipped file is still served.
		if overlay != nil && overlayAllowed(rel) && filepath.IsLocal(rel) {
			if info, err := os.Stat(filepath.Join(staticOverlayDir, rel)); err == nil && !info.IsDir() {
				overlay.ServeHTTP(w, r)
				return
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
