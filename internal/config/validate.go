package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// validSchemes is the closed set of accepted input schemes for v1.
var validSchemes = []string{"https"}

// maxScanTimeout caps the per-scan budget so operators cannot accidentally
// (or maliciously) configure a multi-hour scan. 5 min is well above the
// 30 s default and accommodates manual-pace debugging.
const maxScanTimeout = 5 * time.Minute

// Validate returns the joined set of configuration errors, or nil if the
// config is acceptable.
func (c *Config) Validate() error {
	var errs []error

	if _, _, err := net.SplitHostPort(c.Server.Listen); err != nil {
		errs = append(errs, fmt.Errorf("server.listen: %q is not a valid host:port", c.Server.Listen))
	}

	switch {
	case c.Scan.Timeout.Std() <= 0:
		errs = append(errs, errors.New("scan.timeout: must be > 0"))
	case c.Scan.Timeout.Std() > maxScanTimeout:
		errs = append(errs, fmt.Errorf("scan.timeout: must be <= %s", maxScanTimeout))
	}
	if c.Scan.MaxRedirects < 0 || c.Scan.MaxRedirects > 10 {
		errs = append(errs, fmt.Errorf("scan.max_redirects: must be in [0, 10], got %d", c.Scan.MaxRedirects))
	}

	if len(c.Security.AllowedSchemes) == 0 {
		errs = append(errs, errors.New("security.allowed_schemes: must contain at least one scheme"))
	} else {
		for _, s := range c.Security.AllowedSchemes {
			if !slices.Contains(validSchemes, s) {
				errs = append(errs, fmt.Errorf("security.allowed_schemes: %q is not allowed in v1 (valid: %v)", s, validSchemes))
			}
		}
	}

	if c.Cache.TTL.Std() <= 0 {
		errs = append(errs, errors.New("cache.ttl: must be > 0"))
	}
	if c.Cache.MaxEntries <= 0 {
		errs = append(errs, errors.New("cache.max_entries: must be > 0"))
	}

	if c.History.Enabled {
		if c.History.Retention.Std() <= 0 {
			errs = append(errs, errors.New("history.retention: must be > 0 when history is enabled"))
		}
		if c.History.RateLimit.PerIP.Count <= 0 || c.History.RateLimit.PerIP.Period <= 0 {
			errs = append(errs, errors.New("history.rate_limit.per_ip: invalid"))
		}
		if c.History.RateLimit.PerHost.Count <= 0 || c.History.RateLimit.PerHost.Period <= 0 {
			errs = append(errs, errors.New("history.rate_limit.per_host: invalid"))
		}
	}

	if c.Frontend.BasePath != "/" {
		errs = append(errs, errors.New("frontend.base_path: only '/' is supported"))
	}
	for _, src := range c.Frontend.CSPExtraSources {
		if !validCSPSource(src) {
			errs = append(errs, fmt.Errorf("frontend.csp_extra_sources: %q must be an http(s) origin or a 'sha256-…' hash", src))
		}
	}
	if len(c.Server.TrustedProxies) > 0 {
		errs = append(errs, errors.New("server.trusted_proxies: not supported; must be empty"))
	}
	if c.Telemetry.AnonymousStats {
		errs = append(errs, errors.New("telemetry.anonymous_stats: not supported; must be false"))
	}

	return errors.Join(errs...)
}

// cspHashSource matches a CSP hash source such as 'sha256-<base64>'.
var cspHashSource = regexp.MustCompile(`^'sha(256|384|512)-[A-Za-z0-9+/]+={0,2}'$`)

// validCSPSource accepts an http(s) origin (scheme and host, optional port,
// no path) or a hash source. Anything else, including keywords like
// 'unsafe-inline', separators and whitespace, is rejected so an entry
// cannot weaken or rewrite the policy.
func validCSPSource(s string) bool {
	if cspHashSource.MatchString(s) {
		return true
	}
	if strings.ContainsAny(s, " \t;,'\"") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return false
	}
	return u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}
