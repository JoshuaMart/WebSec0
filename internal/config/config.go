// Package config loads, validates and exposes the websec0.yaml runtime
// configuration.
package config

import "net/netip"

// Config is the parsed top-level configuration.
type Config struct {
	Server    Server    `yaml:"server"`
	Scan      Scan      `yaml:"scan"`
	Security  Security  `yaml:"security"`
	Cache     Cache     `yaml:"cache"`
	History   History   `yaml:"history"`
	Frontend  Frontend  `yaml:"frontend"`
	Telemetry Telemetry `yaml:"telemetry"`
}

// Server holds HTTP listener options.
type Server struct {
	Listen         string   `yaml:"listen"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// Scan holds per-scan engine parameters.
type Scan struct {
	Timeout         Duration `yaml:"timeout"`
	ParallelProbes  bool     `yaml:"parallel_probes"`
	FollowRedirects bool     `yaml:"follow_redirects"`
	MaxRedirects    int      `yaml:"max_redirects"`
}

// Security holds target-safety options (SSRF and DNS-rebinding defences).
type Security struct {
	AllowPrivateTargets bool           `yaml:"allow_private_targets"`
	AllowCustomPorts    bool           `yaml:"allow_custom_ports"`
	AllowedSchemes      []string       `yaml:"allowed_schemes"`
	ExtraBlockedCIDRs   []netip.Prefix `yaml:"extra_blocked_cidrs"`
}

// Cache holds in-memory cache parameters.
type Cache struct {
	TTL        Duration `yaml:"ttl"`
	MaxEntries int      `yaml:"max_entries"`
}

// History holds public-history options and rate limits.
type History struct {
	Enabled   bool          `yaml:"enabled"`
	Retention Duration      `yaml:"retention"`
	RateLimit HistoryLimits `yaml:"rate_limit"`
}

// HistoryLimits expresses the per-IP and per-host limiters.
type HistoryLimits struct {
	PerIP   RateLimit `yaml:"per_ip"`
	PerHost RateLimit `yaml:"per_host"`
}

// Frontend holds embedded-UI options.
type Frontend struct {
	Enabled  bool   `yaml:"enabled"`
	BasePath string `yaml:"base_path"`
}

// Telemetry holds optional anonymous-stats reporting flags.
type Telemetry struct {
	AnonymousStats bool `yaml:"anonymous_stats"`
}
