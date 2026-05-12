// Package frontend embeds the Astro static build and exposes it as an
// http.Handler with SPA fallback. The dist directory is populated by
// `make frontend` (see Makefile) which copies web/dist into here.
//
// A .keep file ships with the repository so the //go:embed directive
// never fails on a fresh clone, but the served content is only useful
// after the frontend has been built.
package frontend

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var rawFS embed.FS

// indexPath is the SPA entry point; every unknown URL falls back to it.
const indexPath = "index.html"

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
func Handler() (http.Handler, error) {
	sub, err := FS()
	if err != nil {
		return nil, err
	}
	indexBytes, err := fs.ReadFile(sub, indexPath)
	if err != nil {
		return nil, ErrIndexMissing
	}
	server := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if rel == "" || rel == indexPath {
			writeIndex(w, indexBytes)
			return
		}
		if info, err := fs.Stat(sub, rel); err == nil && !info.IsDir() {
			server.ServeHTTP(w, r)
			return
		}
		writeIndex(w, indexBytes)
	}), nil
}

func writeIndex(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
