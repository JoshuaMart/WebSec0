// Package catalog hosts the machine-readable checks catalog served at
// GET /api/v1/checks. The JSON file is embedded at compile time, parsed
// + validated at startup, and exposed both as the parsed Catalog struct
// (for in-process lookups) and as the original bytes (for direct HTTP
// serving).
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed checks.json
var raw []byte

// Catalog is the parsed contents of checks.json.
type Catalog struct {
	Version string  `json:"version"`
	Checks  []Check `json:"checks"`
}

// Check is one entry in the catalog.
type Check struct {
	ID               string      `json:"id"`
	Category         string      `json:"category"`
	Title            string      `json:"title"`
	SeverityWhenFail string      `json:"severity_when_fail"`
	ScoreImpact      string      `json:"score_impact,omitempty"`
	Remediation      Remediation `json:"remediation"`
}

// Remediation is the canonical fix recipe associated with a check.
type Remediation struct {
	Summary        string `json:"summary"`
	ExampleStack   string `json:"example_stack,omitempty"`
	ExampleSnippet string `json:"example_snippet,omitempty"`
}

// Load parses and validates the embedded catalog. Callers usually call it
// at startup; the returned Catalog is safe to share read-only.
func Load() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("catalog: parse: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Raw returns the embedded JSON bytes exactly as shipped. Useful for
// HTTP handlers that want byte-for-byte output without re-marshalling.
func Raw() []byte {
	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

// Validate ensures structural integrity: a non-empty version, unique IDs,
// and a non-empty title + remediation summary for every entry.
func (c *Catalog) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("catalog: version is required")
	}
	seen := map[string]struct{}{}
	for i := range c.Checks {
		check := &c.Checks[i]
		if check.ID == "" {
			return fmt.Errorf("catalog: check[%d] has empty id", i)
		}
		if _, dup := seen[check.ID]; dup {
			return fmt.Errorf("catalog: duplicate id %q", check.ID)
		}
		seen[check.ID] = struct{}{}
		if check.Title == "" {
			return fmt.Errorf("catalog: %s: title required", check.ID)
		}
		if check.Remediation.Summary == "" {
			return fmt.Errorf("catalog: %s: remediation.summary required", check.ID)
		}
	}
	return nil
}

// ByID returns the catalog entry with the given id, or nil when not found.
func (c *Catalog) ByID(id string) *Check {
	for i := range c.Checks {
		if c.Checks[i].ID == id {
			return &c.Checks[i]
		}
	}
	return nil
}
