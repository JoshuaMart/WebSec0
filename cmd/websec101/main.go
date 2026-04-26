// Command websec101 is the WebSec101 server binary. It will host the HTTP
// API and the embedded frontend. At Phase 2 it only loads configuration,
// initialises logging, and exits — wiring is added in subsequent phases.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/pflag"

	"github.com/Jomar/websec101/internal/config"
	"github.com/Jomar/websec101/internal/logging"
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

	// Configuration overrides — flag names mirror the koanf keys so they
	// flow straight through the posflag provider.
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

	log.Info("websec101 starting",
		"version", version.Version,
		"commit", version.Commit,
		"listen", cfg.Server.Listen,
		"storage", cfg.Storage.Backend,
	)
	log.Warn("server not yet implemented; exiting (Phase 2 skeleton)")
	return nil
}
