package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestYAML_NotEmpty(t *testing.T) {
	if len(YAML) == 0 {
		t.Fatal("YAML embed is empty — was the openapi.yaml copy step skipped?")
	}
	if !strings.HasPrefix(strings.TrimSpace(string(YAML)), "openapi:") {
		t.Errorf("YAML does not start with `openapi:` — embed broken?\n%.200s", YAML)
	}
}

func TestJSON_RoundTripsAndIsMemoised(t *testing.T) {
	a, err := JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if len(a) == 0 {
		t.Fatal("JSON returned empty bytes")
	}

	b, err := JSON()
	if err != nil {
		t.Fatal(err)
	}
	// Same byte slice (memoised — sync.Once).
	if &a[0] != &b[0] {
		t.Error("JSON not memoised across calls")
	}

	// Round-trip parses as JSON.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}
	for _, k := range []string{"openapi", "info", "paths"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("JSON missing %q key", k)
		}
	}
}

func TestAsRawMap_HasExpectedKeys(t *testing.T) {
	m, err := AsRawMap()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"openapi", "info", "paths", "components"} {
		if _, ok := m[k]; !ok {
			t.Errorf("AsRawMap missing %q", k)
		}
	}
}
