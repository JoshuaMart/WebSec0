package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Load(LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("server.listen = %q, want :8080", cfg.Server.Listen)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("server.read_timeout = %v, want 30s", cfg.Server.ReadTimeout)
	}
	if cfg.Scanner.MaxConcurrentScans != 50 {
		t.Errorf("scanner.max_concurrent_scans = %d, want 50", cfg.Scanner.MaxConcurrentScans)
	}
	if cfg.Scanner.PerCheckTimeout != 8*time.Second {
		t.Errorf("scanner.per_check_timeout = %v, want 8s", cfg.Scanner.PerCheckTimeout)
	}
	if cfg.Storage.Backend != "memory" || cfg.Storage.TTL != 24*time.Hour {
		t.Errorf("unexpected storage defaults: %+v", cfg.Storage)
	}
	if got := cfg.Security.DomainBlocklist; len(got) != 4 || got[0] != ".gov" {
		t.Errorf("security.domain_blocklist = %v", got)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "json" || cfg.Logging.LogTargets {
		t.Errorf("unexpected logging defaults: %+v", cfg.Logging)
	}
}

func TestLoadYAMLOverridesDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  listen: ":9000"
  read_timeout: 10s
scanner:
  max_concurrent_scans: 7
storage:
  backend: ristretto
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(LoadOptions{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":9000" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.ReadTimeout != 10*time.Second {
		t.Errorf("read_timeout = %v", cfg.Server.ReadTimeout)
	}
	if cfg.Scanner.MaxConcurrentScans != 7 {
		t.Errorf("max_concurrent_scans = %d", cfg.Scanner.MaxConcurrentScans)
	}
	if cfg.Storage.Backend != "ristretto" {
		t.Errorf("storage.backend = %q", cfg.Storage.Backend)
	}
	// Untouched defaults must survive.
	if cfg.Server.WriteTimeout != 60*time.Second {
		t.Errorf("write_timeout default leaked: %v", cfg.Server.WriteTimeout)
	}
}

func TestEnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":9000\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("WEBSEC101_SERVER__LISTEN", ":7777")
	t.Setenv("WEBSEC101_SCANNER__PER_CHECK_TIMEOUT", "3s")

	cfg, err := Load(LoadOptions{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":7777" {
		t.Errorf("listen = %q, want :7777 (env should win over YAML)", cfg.Server.Listen)
	}
	if cfg.Scanner.PerCheckTimeout != 3*time.Second {
		t.Errorf("per_check_timeout = %v", cfg.Scanner.PerCheckTimeout)
	}
}

func TestFlagOverridesEnv(t *testing.T) {
	t.Setenv("WEBSEC101_SERVER__LISTEN", ":7777")

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("server.listen", "", "")
	if err := flags.Parse([]string{"--server.listen", ":6543"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	cfg, err := Load(LoadOptions{Flags: flags})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":6543" {
		t.Errorf("listen = %q, want :6543 (flag should win over env)", cfg.Server.Listen)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	t.Setenv("WEBSEC101_STORAGE__BACKEND", "etcd")
	if _, err := Load(LoadOptions{}); err == nil {
		t.Fatal("expected validation error for unknown storage backend")
	}
}
