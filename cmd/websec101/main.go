// Command websec101 is the WebSec101 server binary. It hosts the HTTP API
// (and, in later phases, the embedded frontend).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/Jomar/websec101/internal/api"
	"github.com/Jomar/websec101/internal/checks"
	"github.com/Jomar/websec101/internal/config"
	"github.com/Jomar/websec101/internal/logging"
	"github.com/Jomar/websec101/internal/scanner"
	"github.com/Jomar/websec101/internal/scanner/cookies"
	scannerdns "github.com/Jomar/websec101/internal/scanner/dns"
	"github.com/Jomar/websec101/internal/scanner/email"
	"github.com/Jomar/websec101/internal/scanner/headers"
	scannerhttp "github.com/Jomar/websec101/internal/scanner/http"
	"github.com/Jomar/websec101/internal/scanner/safety"
	scannertls "github.com/Jomar/websec101/internal/scanner/tls"
	"github.com/Jomar/websec101/internal/scanner/wellknown"
	"github.com/Jomar/websec101/internal/storage/memory"
	"github.com/Jomar/websec101/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "websec101:", err)
		os.Exit(1)
	}
}

func run(args []string, errOut *os.File) error {
	flags := pflag.NewFlagSet("websec101", pflag.ContinueOnError)
	flags.SortFlags = false

	configPath := flags.StringP("config", "c", "", "path to YAML config file (optional)")
	showVersion := flags.BoolP("version", "v", false, "print version information and exit")

	flags.String("server.listen", "", "HTTP listen address (e.g. :8080)")
	flags.String("logging.level", "", "log level: debug|info|warn|error")
	flags.String("logging.format", "", "log format: json|text")

	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}
		return err
	}

	if *showVersion {
		info := version.Get()
		_, _ = fmt.Fprintf(errOut, "websec101 %s (commit %s, built %s)\n",
			info.Version, info.Commit, info.BuildDate)
		return nil
	}

	cfg, err := config.Load(config.LoadOptions{
		ConfigPath: *configPath,
		Flags:      flags,
	})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log, err := logging.New(errOut, logging.Options{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
	})
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	slog.SetDefault(log)

	store := memory.New(cfg.Storage.TTL)
	registry := checks.Default()
	wellknown.Register(registry)
	scannertls.Register(registry)
	headers.Register(registry)
	cookies.Register(registry)
	scannerdns.Register(registry)
	email.Register(registry)
	scannerhttp.Register(registry)
	policy, err := safety.FromConfig(safety.ConfigInput{
		RefusePrivateRanges: cfg.Security.RefusePrivateRanges,
		RefuseLoopback:      cfg.Security.RefuseLoopback,
		RefuseCGNAT:         cfg.Security.RefuseCGNAT,
		RefuseLinkLocal:     cfg.Security.RefuseLinkLocal,
		RefuseMetadata:      cfg.Security.RefuseMetadata,
		DomainBlocklist:     cfg.Security.DomainBlocklist,
		AllowedCIDRs:        cfg.Security.AllowedCIDRs,
		AllowedHosts:        cfg.Security.AllowedHosts,
	})
	if err != nil {
		return fmt.Errorf("invalid security config: %w", err)
	}
	if !cfg.Security.RefuseMetadata {
		log.Warn("security.refuse_metadata is FALSE — cloud-metadata endpoints can be reached. " +
			"Disable only on lab/airgapped deployments.")
	}

	mgr := scanner.NewManager(store, registry, scanner.ManagerConfig{
		MaxConcurrentScans:         cfg.Scanner.MaxConcurrentScans,
		MaxConcurrentChecksPerScan: cfg.Scanner.MaxConcurrentChecksPerScan,
		PerCheckTimeout:            cfg.Scanner.PerCheckTimeout,
		PerScanTimeout:             cfg.Scanner.PerScanTimeout,
		StorageTTL:                 cfg.Storage.TTL,
	}, log)

	handler, err := api.NewServer(api.Options{
		Logger:         log,
		Store:          store,
		Registry:       registry,
		Scans:          mgr,
		Policy:         policy,
		PerScanTimeout: cfg.Scanner.PerScanTimeout,
		LogTargets:     cfg.Logging.LogTargets,
	})
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       2 * cfg.Server.WriteTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("websec101 listening",
			"version", version.Version,
			"commit", version.Commit,
			"listen", cfg.Server.Listen,
			"storage", cfg.Storage.Backend,
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("server stopped")
	return nil
}
