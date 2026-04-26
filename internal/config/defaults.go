package config

// Defaults returns the flat key→value map applied as the lowest-precedence
// configuration layer. Values match SPECIFICATIONS.md §4.6.
func Defaults() map[string]any {
	return map[string]any{
		"server.listen":        ":8080",
		"server.read_timeout":  "30s",
		"server.write_timeout": "60s",

		"scanner.max_concurrent_scans":           50,
		"scanner.max_concurrent_checks_per_scan": 10,
		"scanner.per_check_timeout":              "8s",
		"scanner.per_scan_timeout":               "120s",
		"scanner.user_agent":                     "WebSec101/0.1.0 (+https://websec101.example/about; passive-scan)",

		"storage.backend":   "memory",
		"storage.ttl":       "24h",
		"storage.redis.url": "",

		"ratelimit.per_ip.rate":         10,
		"ratelimit.per_ip.period":       "1h",
		"ratelimit.per_target.cooldown": "5m",

		"security.refuse_private_ranges": true,
		"security.refuse_loopback":       true,
		"security.refuse_cgnat":          true,
		"security.refuse_link_local":     true,
		"security.refuse_metadata":       true,
		"security.domain_blocklist":      []string{".gov", ".mil", ".gouv.fr", ".gc.ca"},
		"security.allowed_cidrs":         []string{},
		"security.allowed_hosts":         []string{},

		"reports.default_visibility":  "public",
		"reports.private_token_bytes": 32,

		"logging.level":       "info",
		"logging.format":      "json",
		"logging.log_targets": false,
	}
}
