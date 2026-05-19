// Command websec0 is the HTTP scanner daemon. It loads configuration,
// wires the scan engine and the chi router, and starts an http.Server
// listening on the configured address. SIGINT/SIGTERM trigger a graceful
// shutdown bounded by the configured scan.timeout (plus a small grace
// margin) so in-flight scans get a chance to complete.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JoshuaMart/websec0/internal/api"
	"github.com/JoshuaMart/websec0/internal/config"
	"github.com/JoshuaMart/websec0/internal/scanner"
	"github.com/JoshuaMart/websec0/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to websec0.yaml (overrides auto-discovery)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return nil
	}

	cfg, source, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if cfg.Log.DebugHandshakes {
		// Surfaces the per-handshake diagnostic log emitted by
		// internal/tls.attemptHandshake. Useful when a target stops
		// responding mid-scan and we want to correlate the bascule with a
		// specific protocol/cipher pair.
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	if source == "" {
		source = "<defaults>"
	}
	logger.Info("starting",
		slog.String("version", version.Version),
		slog.String("commit", version.Commit),
		slog.String("config_source", source),
	)

	sc := scanner.New(cfg)
	router := api.NewRouter(api.Deps{
		Scanner: sc,
		Config:  cfg,
		Logger:  logger,
	})

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server: %w", err)
	case <-sigCtx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Scan.Timeout.Std()+5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}

// loadConfig resolves the configuration. An explicit --config flag wins
// over the auto-discovery search ($WEBSEC0_CONFIG → cwd → /etc).
func loadConfig(explicit string) (*config.Config, string, error) {
	if explicit != "" {
		cfg, err := config.LoadFile(explicit)
		if err != nil {
			return nil, "", err
		}
		return cfg, explicit, nil
	}
	return config.Load()
}
