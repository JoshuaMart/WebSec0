// Package logging builds the process-wide *slog.Logger from a LoggingConfig.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Options mirrors the resolved values from config.LoggingConfig. Defined as
// its own struct here to keep this package independent of internal/config.
type Options struct {
	Level  string // debug | info | warn | error
	Format string // json | text
}

// New returns a configured *slog.Logger writing to w. Pass os.Stderr in
// production. Returns an error for malformed level/format strings.
func New(w io.Writer, opts Options) (*slog.Logger, error) {
	if w == nil {
		w = os.Stderr
	}

	var lvl slog.Level
	switch strings.ToLower(opts.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "", "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("logging: unknown level %q", opts.Level)
	}

	handlerOpts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	switch strings.ToLower(opts.Format) {
	case "", "json":
		handler = slog.NewJSONHandler(w, handlerOpts)
	case "text":
		handler = slog.NewTextHandler(w, handlerOpts)
	default:
		return nil, fmt.Errorf("logging: unknown format %q", opts.Format)
	}

	return slog.New(handler), nil
}
