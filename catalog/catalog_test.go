package catalog

import (
	"encoding/json"
	"testing"
)

func TestLoad_ParsesEmbeddedCatalog(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Version == "" {
		t.Error("version: missing")
	}
	if len(c.Checks) == 0 {
		t.Error("checks: empty")
	}
}

func TestValidate_UniqueIDs(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, check := range c.Checks {
		if seen[check.ID] {
			t.Errorf("duplicate id: %s", check.ID)
		}
		seen[check.ID] = true
	}
}

func TestValidate_AllEntriesHaveRemediation(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range c.Checks {
		if check.Remediation.Summary == "" {
			t.Errorf("%s: remediation.summary empty", check.ID)
		}
	}
}

func TestValidate_DuplicateIDFails(t *testing.T) {
	c := &Catalog{
		Version: "1.0.0",
		Checks: []Check{
			{ID: "x", Title: "X", Remediation: Remediation{Summary: "do it"}},
			{ID: "x", Title: "X again", Remediation: Remediation{Summary: "do it"}},
		},
	}
	if err := c.Validate(); err == nil {
		t.Error("expected duplicate ID error")
	}
}

func TestValidate_MissingSummaryFails(t *testing.T) {
	c := &Catalog{
		Version: "1.0.0",
		Checks:  []Check{{ID: "x", Title: "X"}},
	}
	if err := c.Validate(); err == nil {
		t.Error("expected missing-summary error")
	}
}

func TestByID(t *testing.T) {
	c, _ := Load()
	for _, knownID := range []string{
		"tls.protocol.sslv2",
		"tls.protocol.tls13",
		"tls.chain.expired",
		"headers.strict_transport_security",
		"headers.content_security_policy",
		"custom.security_txt",
		"custom.robots_txt",
	} {
		if c.ByID(knownID) == nil {
			t.Errorf("ByID(%q): not found", knownID)
		}
	}
	if c.ByID("nope.does.not.exist") != nil {
		t.Error("unknown ID should return nil")
	}
}

func TestRaw_ReturnsValidJSON(t *testing.T) {
	body := Raw()
	if len(body) == 0 {
		t.Fatal("Raw() returned empty bytes")
	}
	var anything map[string]any
	if err := json.Unmarshal(body, &anything); err != nil {
		t.Errorf("Raw bytes are not valid JSON: %v", err)
	}
	// Mutating the returned slice must not affect future calls.
	body[0] = '!'
	again := Raw()
	if again[0] == '!' {
		t.Error("Raw() returned an aliased slice")
	}
}

func TestKnownCategoriesCovered(t *testing.T) {
	c, _ := Load()
	wantCategories := []string{
		"tls.protocol",
		"tls.chain",
		"tls.cipher",
		"tls.vulnerability",
		"headers.core",
		"headers.additional",
		"custom",
	}
	categories := map[string]bool{}
	for _, ch := range c.Checks {
		categories[ch.Category] = true
	}
	for _, want := range wantCategories {
		if !categories[want] {
			t.Errorf("missing category in catalog: %s", want)
		}
	}
}
