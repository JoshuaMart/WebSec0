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
	IPLimiter      *ratelimit.IPLimiter     // optional; nil disables per-IP rate limiting
	Tracker        *ratelimit.TargetTracker // optional; nil disables cooldown/cache/abuse
	AuditLog       *audit.Logger            // optional; nil disables audit
	PerScanTimeout time.Duration
	LogTargets     bool     // honour logging.log_targets
	CORSOrigin     []string // CORS allowlist; nil → "https://*"
}

// NewServer returns the root http.Handler for the WebSec101 API.
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
	if opts.IPLimiter != nil {
		r.Use(opts.IPLimiter.Middleware())
	}

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
	r.Handle("/*", frontendHandler(staticFS))

	return r, nil
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
