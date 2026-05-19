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
	Log       Log       `yaml:"log"`
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
	// HeadInject is a raw HTML fragment spliced just before </head> in
	// every embedded shell page (landing + report). Intended for opt-in
	// analytics on a public deployment (Umami, Plausible, …). Empty by
	// default so self-hosters get an untouched bundle. The string is
	// trusted operator-supplied content — not escaped.
	HeadInject string `yaml:"head_inject"`
	// StaticOverlayDir, when non-empty, is a directory whose layout
	// mirrors URL paths. Files inside are served verbatim and take
	// precedence over anything embedded in the binary:
	//
	//   <dir>/.well-known/security.txt → /.well-known/security.txt
	//   <dir>/robots.txt               → /robots.txt
	//   <dir>/humans.txt               → /humans.txt
	//
	// Anything under .well-known/ is always allowed; at the root only a
	// closed whitelist of static files is honoured so a misconfigured
	// overlay cannot hijack the SPA shell (e.g. index.html). Paths
	// absent from the overlay fall back to the embedded fs.
	StaticOverlayDir string `yaml:"static_overlay_dir"`
}

// Telemetry holds optional anonymous-stats reporting flags.
type Telemetry struct {
	AnonymousStats bool `yaml:"anonymous_stats"`
}

// Log holds runtime logging knobs.
type Log struct {
	// DebugHandshakes raises the slog level to Debug, which makes the
	// per-handshake diagnostic line (`msg=handshake seq=… err_kind=…`)
	// emitted by internal/tls.attemptHandshake visible on stderr. Useful
	// when a target stops responding mid-scan and we need to correlate the
	// bascule with a specific protocol/cipher pair. Off by default —
	// the volume is ~450 lines per scan worst case.
	DebugHandshakes bool `yaml:"debug_handshakes"`
}
