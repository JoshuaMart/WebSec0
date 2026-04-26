// Package api wires the chi router, middlewares, and the ogen-generated
// server into a single http.Handler.
package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Jomar/websec101/internal/api/handlers"
	mw "github.com/Jomar/websec101/internal/api/middleware"
	"github.com/Jomar/websec101/internal/api/spec"
	"github.com/Jomar/websec101/internal/storage"
	client "github.com/Jomar/websec101/pkg/client"
)

// Options configures NewServer.
type Options struct {
	Logger     *slog.Logger
	Store      storage.ScanStore
	LogTargets bool     // honour logging.log_targets
	CORSOrigin []string // CORS allowlist; nil → "https://*"
}

// NewServer returns the root http.Handler for the WebSec101 API.
//
// Layout:
//
//	chi.Router (request-id, recover, access-log, cors)
//	└── ogen.Server (mounted at "/", spec paths already include /api/v1)
func NewServer(opts Options) (http.Handler, error) {
	if opts.Logger == nil {
		return nil, fmt.Errorf("api: Logger is required")
	}

	h := handlers.New(opts.Store)

	ogenServer, err := client.NewServer(h,
		client.WithErrorHandler(handlers.ErrorHandler),
	)
	if err != nil {
		return nil, fmt.Errorf("api: build ogen server: %w", err)
	}

	r := chi.NewRouter()
	r.Use(mw.RequestID)
	r.Use(mw.Recover(opts.Logger))
	r.Use(mw.AccessLog(opts.Logger, opts.LogTargets))
	r.Use(mw.CORS(mw.CORSOptions{AllowedOrigins: opts.CORSOrigin}))

	// Sanity-check the embedded spec at startup so a broken openapi.yaml
	// fails fast instead of surfacing on the first /openapi.json hit.
	if _, err := spec.JSON(); err != nil {
		return nil, fmt.Errorf("api: load embedded openapi: %w", err)
	}

	r.Mount("/", ogenServer)
	return r, nil
}
