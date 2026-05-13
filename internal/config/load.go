package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// Environment variable and default paths used by Load.
const (
	EnvConfigPath = "WEBSEC0_CONFIG"
	PathCwd       = "websec0.yaml"
	PathSystem    = "/etc/websec0/websec0.yaml"
)

// Load resolves the configuration:
// - $WEBSEC0_CONFIG, if set, is treated as an explicit path: missing → error.
// - Otherwise ./websec0.yaml then /etc/websec0/websec0.yaml are tried, and
// a missing file falls through to the next candidate.
// - If no file is found at all, validated defaults are returned with an
// empty source path.
func Load() (*Config, string, error) {
	if explicit := os.Getenv(EnvConfigPath); explicit != "" {
		cfg, err := LoadFile(explicit)
		if err != nil {
			return nil, "", err
		}
		return cfg, explicit, nil
	}
	for _, p := range []string{PathCwd, PathSystem} {
		cfg, err := LoadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return cfg, p, nil
	}
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("default config invalid: %w", err)
	}
	return cfg, "", nil
}

// LoadFile reads, decodes (strictly — unknown fields are rejected) and
// validates a YAML configuration at the given path.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}
