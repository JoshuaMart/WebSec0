package config

import "time"

// Defaults returns a Config populated with the values
// The returned pointer is safe to mutate by the caller (e.g. a YAML decoder
// merging user-provided overrides on top).
func Defaults() *Config {
	return &Config{
		Server: Server{
			Listen:         "0.0.0.0:8080",
			TrustedProxies: []string{},
		},
		Scan: Scan{
			Timeout:         Duration(30 * time.Second),
			ParallelProbes:  true,
			FollowRedirects: true,
			MaxRedirects:    3,
		},
		Security: Security{
			AllowPrivateTargets: false,
			AllowCustomPorts:    false,
			AllowedSchemes:      []string{"https"},
		},
		Cache: Cache{
			TTL:        Duration(24 * time.Hour),
			MaxEntries: 1000,
		},
		History: History{
			Enabled:   true,
			Retention: Duration(7 * 24 * time.Hour),
			RateLimit: HistoryLimits{
				PerIP:   RateLimit{Count: 10, Period: time.Hour},
				PerHost: RateLimit{Count: 1, Period: time.Minute},
			},
		},
		Frontend: Frontend{
			Enabled:  true,
			BasePath: "/",
		},
		Telemetry: Telemetry{
			AnonymousStats: false,
		},
	}
}
