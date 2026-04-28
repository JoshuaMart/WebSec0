// Package api wires the chi router, middlewares, and the ogen-generated
// server into a single http.Handler.
package api

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/JoshuaMart/websec0/internal/api/handlers"
	mw "github.com/JoshuaMart/websec0/internal/api/middleware"
	"github.com/JoshuaMart/websec0/internal/api/spec"
	"github.com/JoshuaMart/websec0/internal/audit"
	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/ratelimit"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/JoshuaMart/websec0/internal/scanner/safety"
	"github.com/JoshuaMart/websec0/internal/storage"
	"github.com/JoshuaMart/websec0/internal/webfs"
	client "github.com/JoshuaMart/websec0/pkg/client"
)

// Options configures NewServer.
type Options struct {
	Logger         *slog.Logger
	Store          storage.ScanStore
	Registry       *checks.Registry
	Scans          *scanner.Manager
	Policy         *safety.Policy
	IPLimiter      *ratelimit.IPLimiter     // optional; nil disables per-IP scan-creation cap
	Tracker        *ratelimit.TargetTracker // optional; nil disables cooldown/cache/abuse
	AuditLog       *audit.Logger            // optional; nil disables audit
	PerScanTimeout time.Duration
	LogTargets     bool     // honour logging.log_targets
	CORSOrigin     []string // CORS allowlist; nil → "https://*"
}

// NewServer returns the root http.Handler for the WebSec0 API.
//
// Layout:
//
//	chi.Router (request-id, recover, access-log, cors)
//	├── GET /api/v1/scans/{guid}/events  — explicit SSE route
//	├── /api/*                           — ogen.Server
//	└── /*                               — embedded Astro static frontend
//
// The SSE endpoint is registered on chi directly (and matched first)
// because it does not fit the OpenAPI request/response model: streaming,
// long-lived, EventSource semantics.
func NewServer(opts Options) (http.Handler, error) {
	if opts.Logger == nil {
		return nil, fmt.Errorf("api: Logger is required")
	}

	registry := opts.Registry
	if registry == nil {
		registry = checks.NewRegistry()
	}

	h := handlers.New(handlers.Options{
		Store:          opts.Store,
		Registry:       registry,
		Scans:          opts.Scans,
		Policy:         opts.Policy,
		Tracker:        opts.Tracker,
		IPLimiter:      opts.IPLimiter,
		AuditLog:       opts.AuditLog,
		PerScanTimeout: opts.PerScanTimeout,
	})

	ogenServer, err := client.NewServer(h,
		client.WithErrorHandler(handlers.ErrorHandler),
	)
	if err != nil {
		return nil, fmt.Errorf("api: build ogen server: %w", err)
	}

	r := chi.NewRouter()
	r.Use(mw.RequestID)
	r.Use(mw.SourceIP)
	r.Use(mw.Recover(opts.Logger))
	r.Use(mw.AccessLog(opts.Logger, opts.LogTargets))
	r.Use(mw.CORS(mw.CORSOptions{AllowedOrigins: opts.CORSOrigin}))

	// The per-IP scan-creation cap (opts.IPLimiter) is enforced inside the
	// CreateScan handler, not here, so static assets, the SSE stream, and
	// result polling are not throttled.

	if _, err := spec.JSON(); err != nil {
		return nil, fmt.Errorf("api: load embedded openapi: %w", err)
	}

	// Explicit SSE route — takes precedence over the ogen mount below.
	r.Get("/api/v1/scans/{guid}/events", h.SSEHandler)

	// All /api/* requests go to the ogen server.
	r.Mount("/api", ogenServer)

	// Frontend — embedded Astro static build.
	// Falls back gracefully when dist/ is empty (pre-build).
	staticFS, err := webfs.FS()
	if err != nil {
		return nil, fmt.Errorf("api: load embedded frontend: %w", err)
	}

	// Scan report pages — serve the same static shell for any /scan/{guid}/ URL.
	// Alpine.js reads the GUID from window.location and fetches the API.
	scanShell := scanShellHandler(staticFS)
	r.Get("/scan/{guid}", scanShell)
	r.Get("/scan/{guid}/", scanShell)

	r.Handle("/*", frontendHandler(staticFS))

	return r, nil
}

// scanShellHandler serves the pre-built scan/index.html for any /scan/{guid}/ path.
// The file is read once from the embedded FS; cache-control is set to no-store so
// browsers always get fresh state when navigating back.
func scanShellHandler(fsys fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(fsys, "scan/index.html")
		if err != nil {
			http.Error(w, "Frontend not built. Run 'make web' first.", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store")
		_, _ = w.Write(data)
	}
}

// frontendHandler serves static files from the embedded Astro dist/.
// For paths that map to a directory, it tries index.html (Astro's default).
// Unknown paths return 404 without panicking.
func frontendHandler(fsys fs.FS) http.Handler {
	fileServer := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	})
}
