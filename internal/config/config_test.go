package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "websec0.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults_Validate(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("defaults must validate, got: %v", err)
	}
}

func TestLoadFile_OverridesMergeOnDefaults(t *testing.T) {
	p := writeYAML(t, "scan:\n  timeout: 30s\n")
	cfg, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Timeout.Std() != 30*time.Second {
		t.Errorf("scan.timeout: want 30s, got %s", cfg.Scan.Timeout.Std())
	}
	if cfg.Cache.MaxEntries != 1000 {
		t.Errorf("cache.max_entries default not preserved: got %d", cfg.Cache.MaxEntries)
	}
	if !cfg.Scan.ParallelProbes {
		t.Error("scan.parallel_probes default not preserved")
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	p := writeYAML(t, "scan: {timeout: [")
	if _, err := LoadFile(p); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadFile_UnknownKeyRejected(t *testing.T) {
	p := writeYAML(t, "unknown_top_level: 1\n")
	if _, err := LoadFile(p); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestLoadFile_BadCIDR(t *testing.T) {
	p := writeYAML(t, "security:\n  extra_blocked_cidrs: [\"not-a-cidr\"]\n")
	if _, err := LoadFile(p); err == nil {
		t.Fatal("expected CIDR parse error")
	}
}

func TestLoadFile_GoodCIDRs(t *testing.T) {
	p := writeYAML(t, "security:\n  extra_blocked_cidrs: [\"10.20.0.0/16\", \"2001:db8::/32\"]\n")
	cfg, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(cfg.Security.ExtraBlockedCIDRs) != 2 ||
		cfg.Security.ExtraBlockedCIDRs[0] != want[0] ||
		cfg.Security.ExtraBlockedCIDRs[1] != want[1] {
		t.Errorf("got %v, want %v", cfg.Security.ExtraBlockedCIDRs, want)
	}
}

func TestLoadFile_BadDuration(t *testing.T) {
	p := writeYAML(t, "scan:\n  timeout: 15z\n")
	if _, err := LoadFile(p); err == nil {
		t.Fatal("expected duration parse error")
	}
}

func TestLoadFile_RejectsHTTPScheme(t *testing.T) {
	p := writeYAML(t, "security:\n  allowed_schemes: [\"http\"]\n")
	_, err := LoadFile(p)
	if err == nil || !strings.Contains(err.Error(), "allowed_schemes") {
		t.Fatalf("expected allowed_schemes error, got: %v", err)
	}
}

func TestLoadFile_TimeoutTooLarge(t *testing.T) {
	p := writeYAML(t, "scan:\n  timeout: 10m\n")
	_, err := LoadFile(p)
	if err == nil || !strings.Contains(err.Error(), "scan.timeout") {
		t.Fatalf("expected scan.timeout cap error, got: %v", err)
	}
}

func TestLoadFile_BadListen(t *testing.T) {
	p := writeYAML(t, "server:\n  listen: \"not-a-host-port\"\n")
	_, err := LoadFile(p)
	if err == nil || !strings.Contains(err.Error(), "server.listen") {
		t.Fatalf("expected server.listen error, got: %v", err)
	}
}

func TestLoadFile_FrontendBasePath(t *testing.T) {
	p := writeYAML(t, "frontend:\n  base_path: \"no-leading-slash\"\n")
	_, err := LoadFile(p)
	if err == nil || !strings.Contains(err.Error(), "frontend.base_path") {
		t.Fatalf("expected frontend.base_path error, got: %v", err)
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	p := writeYAML(t, "scan:\n  timeout: 7s\n")
	t.Setenv(EnvConfigPath, p)

	cfg, src, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if src != p {
		t.Errorf("source: want %s, got %s", p, src)
	}
	if cfg.Scan.Timeout.Std() != 7*time.Second {
		t.Errorf("scan.timeout: want 7s, got %s", cfg.Scan.Timeout.Std())
	}
}

func TestLoad_EnvPointsToMissingFile(t *testing.T) {
	t.Setenv(EnvConfigPath, filepath.Join(t.TempDir(), "nope.yaml"))
	if _, _, err := Load(); err == nil {
		t.Fatal("expected error when env-pointed config is missing")
	}
}

func TestLoad_DefaultsWhenNoFile(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(EnvConfigPath, "")
	cfg, src, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if src != "" {
		t.Errorf("expected empty source (defaults), got %s", src)
	}
	if cfg.Cache.MaxEntries != 1000 {
		t.Errorf("defaults not applied: %+v", cfg.Cache)
	}
}

func TestParseRateLimit(t *testing.T) {
	type want struct {
		ok     bool
		count  int
		period time.Duration
	}
	cases := map[string]want{
		"10/hour":  {true, 10, time.Hour},
		"1/minute": {true, 1, time.Minute},
		"5/sec":    {true, 5, time.Second},
		"100/day":  {true, 100, 24 * time.Hour},
		"50/h":     {true, 50, time.Hour},
		"foo":      {ok: false},
		"0/hour":   {ok: false},
		"-1/hour":  {ok: false},
		"10/year":  {ok: false},
		"10/":      {ok: false},
		"/hour":    {ok: false},
	}
	for in, w := range cases {
		got, err := parseRateLimit(in)
		if w.ok {
			if err != nil {
				t.Errorf("%q: unexpected error %v", in, err)
				continue
			}
			if got.Count != w.count || got.Period != w.period {
				t.Errorf("%q: got %+v, want count=%d period=%s", in, got, w.count, w.period)
			}
		} else if err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestParseDuration_DaysSupport(t *testing.T) {
	got, err := parseDuration("7d")
	if err != nil {
		t.Fatal(err)
	}
	if got != 7*24*time.Hour {
		t.Errorf("7d: got %s, want 168h", got)
	}
}

func TestParseDuration_StdlibForms(t *testing.T) {
	for _, in := range []string{"15s", "5m", "24h", "1h30m", "500ms"} {
		if _, err := parseDuration(in); err != nil {
			t.Errorf("%q: unexpected error %v", in, err)
		}
	}
}

func TestRateLimit_YAMLUnmarshal(t *testing.T) {
	var rl RateLimit
	if err := yaml.Unmarshal([]byte(`"10/hour"`), &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Count != 10 || rl.Period != time.Hour {
		t.Errorf("got %+v", rl)
	}
}

func TestValidate_ErrorsAreJoined(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Listen = "junk"
	cfg.Cache.MaxEntries = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "server.listen") ||
		!strings.Contains(err.Error(), "cache.max_entries") {
		t.Errorf("joined error should mention both fields, got: %v", err)
	}
	// errors.Join returns an error that errors.Unwrap (multi) can split.
	var u interface{ Unwrap() []error }
	if !errors.As(err, &u) {
		t.Error("expected joined error to expose Unwrap() []error")
	}
}
