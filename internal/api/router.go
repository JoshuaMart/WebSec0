// Package api hosts the HTTP routing layer: a chi router that exposes
// /api/v1/scan (POST + GET by id) and /api/v1/checks, wired with
// request-ID, slog request logger, panic recovery and per-IP rate limiting.
// All inbound JSON shapes and error codes follow SPEC §6.
package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/history"
	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// ScanService is the subset of scanner.Scanner the API depends on.
// scanner.Scanner satisfies this interface; tests inject a fake to bypass
// the real DNS + probe pipeline.
type ScanService interface {
	Run(ctx context.Context, req scanner.Request) (*scan.Result, error)
	Get(id string) (*scan.Result, bool)
	History(limit int) []history.Entry
}

// Deps groups the runtime dependencies used to build a router.
type Deps struct {
	Scanner ScanService
	Config  *config.Config
	Logger  *slog.Logger
}

// NewRouter returns a chi.Mux mounting the API and its middleware stack.
// The caller embeds it in their http.Server.
func NewRouter(d Deps) *chi.Mux {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(slogRequestLogger(logger))

	ipLimiter := safehttp.NewLimiter(d.Config.History.RateLimit.PerIP.Count, d.Config.History.RateLimit.PerIP.Period)
	hostLimiter := safehttp.NewLimiter(d.Config.History.RateLimit.PerHost.Count, d.Config.History.RateLimit.PerHost.Period)

	r.Route("/api/v1", func(r chi.Router) {
		r.With(perIPRateLimit(ipLimiter)).Post("/scan", scanPostHandler(d.Scanner, hostLimiter))
		r.Get("/scan/{id}", scanGetHandler(d.Scanner))
		r.Get("/checks", checksHandler())
		r.Get("/history", historyHandler(d.Scanner))
	})

	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "route does not exist")
	})
	return r
}
