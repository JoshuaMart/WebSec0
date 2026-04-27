// Package config loads the websec0 configuration from defaults, an optional
// YAML file, environment variables prefixed with WEBSEC101_, and CLI flags.
//
// Precedence (lowest to highest): defaults < YAML < env < flags.
//
// Env variables use double underscores to denote key nesting:
//
//	WEBSEC101_SERVER__LISTEN=":9090"        // → server.listen
//	WEBSEC101_SCANNER__PER_CHECK_TIMEOUT=5s // → scanner.per_check_timeout
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// EnvPrefix is the env-var prefix used for configuration overrides.
const EnvPrefix = "WEBSEC101_"

// Config is the typed configuration tree. It mirrors the YAML schema
// documented in SPECIFICATIONS.md §4.6.
type Config struct {
	Server    ServerConfig    `koanf:"server"`
	Scanner   ScannerConfig   `koanf:"scanner"`
	Storage   StorageConfig   `koanf:"storage"`
	RateLimit RateLimitConfig `koanf:"ratelimit"`
	Security  SecurityConfig  `koanf:"security"`
	Reports   ReportsConfig   `koanf:"reports"`
	Logging   LoggingConfig   `koanf:"logging"`
}

type ServerConfig struct {
	Listen       string        `koanf:"listen"`
	ReadTimeout  time.Duration `koanf:"read_timeout"`
	WriteTimeout time.Duration `koanf:"write_timeout"`
}

type ScannerConfig struct {
	MaxConcurrentScans         int           `koanf:"max_concurrent_scans"`
	MaxConcurrentChecksPerScan int           `koanf:"max_concurrent_checks_per_scan"`
	PerCheckTimeout            time.Duration `koanf:"per_check_timeout"`
	PerScanTimeout             time.Duration `koanf:"per_scan_timeout"`
	UserAgent                  string        `koanf:"user_agent"`
}

type StorageConfig struct {
	Backend string        `koanf:"backend"` // memory | ristretto | redis
	TTL     time.Duration `koanf:"ttl"`
	Redis   RedisConfig   `koanf:"redis"`
}

type RedisConfig struct {
	URL string `koanf:"url"`
}

type RateLimitConfig struct {
	PerIP     PerIPLimit     `koanf:"per_ip"`
	PerTarget PerTargetLimit `koanf:"per_target"`
}

type PerIPLimit struct {
	Rate   int           `koanf:"rate"`
	Period time.Duration `koanf:"period"`
}

type PerTargetLimit struct {
	Cooldown time.Duration `koanf:"cooldown"`
}

type SecurityConfig struct {
	RefusePrivateRanges bool `koanf:"refuse_private_ranges"`
	RefuseLoopback      bool `koanf:"refuse_loopback"`
	RefuseCGNAT         bool `koanf:"refuse_cgnat"`
	RefuseLinkLocal     bool `koanf:"refuse_link_local"`
	// RefuseMetadata is a separate hard-toggle from RefusePrivateRanges:
	// disabling metadata blocking on a cloud host is essentially a
	// pre-authorised IAM-credential heist, so we keep it default-true
	// and log a WARN at startup if it's flipped off.
	RefuseMetadata  bool     `koanf:"refuse_metadata"`
	DomainBlocklist []string `koanf:"domain_blocklist"`
	AllowedCIDRs    []string `koanf:"allowed_cidrs"`
	AllowedHosts    []string `koanf:"allowed_hosts"`
}

type ReportsConfig struct {
	DefaultVisibility string `koanf:"default_visibility"` // public | private
	PrivateTokenBytes int    `koanf:"private_token_bytes"`
}

type LoggingConfig struct {
	Level      string `koanf:"level"`  // debug | info | warn | error
	Format     string `koanf:"format"` // json | text
	LogTargets bool   `koanf:"log_targets"`
}

// LoadOptions controls Load behaviour.
type LoadOptions struct {
	// ConfigPath, if non-empty, points at a YAML file. A missing file is
	// silently ignored so the binary works without config on a fresh install.
	ConfigPath string
	// Flags is an already-parsed pflag.FlagSet whose long-name keys (using
	// dots, e.g. "server.listen") override env and YAML values. May be nil.
	Flags *pflag.FlagSet
}

// Load assembles a *Config from defaults, file, env, and flags in order.
func Load(opts LoadOptions) (*Config, error) {
	k := koanf.New(".")

	if err := k.Load(confmap.Provider(Defaults(), "."), nil); err != nil {
		return nil, fmt.Errorf("load defaults: %w", err)
	}

	if opts.ConfigPath != "" {
		if err := k.Load(file.Provider(opts.ConfigPath), yaml.Parser()); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("load config %q: %w", opts.ConfigPath, err)
			}
		}
	}

	envProvider := env.Provider(EnvPrefix, ".", envKeyTransform)
	if err := k.Load(envProvider, nil); err != nil {
		return nil, fmt.Errorf("load env: %w", err)
	}

	if opts.Flags != nil {
		if err := k.Load(posflag.Provider(opts.Flags, ".", k), nil); err != nil {
			return nil, fmt.Errorf("load flags: %w", err)
		}
	}

	cfg := &Config{}
	if err := k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			Result:           cfg,
			TagName:          "koanf",
			WeaklyTypedInput: true,
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			),
		},
	}); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// envKeyTransform maps WEBSEC101_FOO__BAR_BAZ → foo.bar_baz.
// Single underscores are preserved (they are part of key names like
// "read_timeout"); double underscores denote nesting.
func envKeyTransform(s string) string {
	s = strings.TrimPrefix(s, EnvPrefix)
	s = strings.ToLower(s)
	return strings.ReplaceAll(s, "__", ".")
}

func (c *Config) validate() error {
	switch c.Storage.Backend {
	case "memory", "ristretto", "redis":
	default:
		return fmt.Errorf("storage.backend: must be one of memory|ristretto|redis (got %q)", c.Storage.Backend)
	}
	switch c.Reports.DefaultVisibility {
	case "public", "private":
	default:
		return fmt.Errorf("reports.default_visibility: must be public|private (got %q)", c.Reports.DefaultVisibility)
	}
	switch c.Logging.Format {
	case "json", "text":
	default:
		return fmt.Errorf("logging.format: must be json|text (got %q)", c.Logging.Format)
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level: must be debug|info|warn|error (got %q)", c.Logging.Level)
	}
	if c.Scanner.MaxConcurrentScans < 1 {
		return fmt.Errorf("scanner.max_concurrent_scans: must be ≥ 1")
	}
	if c.Scanner.MaxConcurrentChecksPerScan < 1 {
		return fmt.Errorf("scanner.max_concurrent_checks_per_scan: must be ≥ 1")
	}
	return nil
}
