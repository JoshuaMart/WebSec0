package email

import (
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// TestRegister_AllChecksHaveValidMetadata exercises the static metadata
// surface (ID/Family/DefaultSeverity/Title/Description/RFCRefs) of
// every Check the package registers. The orchestrator catalogues these
// at boot via Catalog(); guarantees them here so the family stays
// machine-readable without running a real scan.
func TestRegister_AllChecksHaveValidMetadata(t *testing.T) {
	r := checks.NewRegistry()
	Register(r)
	if r.Len() == 0 {
		t.Fatal("Register added zero checks")
	}
	for _, c := range r.All() {
		if c.ID() == "" {
			t.Errorf("check %T returned empty ID", c)
		}
		if !strings.HasPrefix(c.ID(), "EMAIL-") {
			t.Errorf("%s does not start with EMAIL-", c.ID())
		}
		if c.Family() != checks.FamilyEmail {
			t.Errorf("%s family = %s, want email", c.ID(), c.Family())
		}
		// DefaultSeverity must be one of the canonical values.
		switch c.DefaultSeverity() {
		case checks.SeverityInfo, checks.SeverityLow,
			checks.SeverityMedium, checks.SeverityHigh, checks.SeverityCritical:
		default:
			t.Errorf("%s severity = %q, not canonical", c.ID(), c.DefaultSeverity())
		}
		// Optional Describer surface — when present, exercise it.
		if d, ok := c.(checks.Describer); ok {
			if d.Title() == "" {
				t.Errorf("%s Title() is empty", c.ID())
			}
			if d.Description() == "" {
				t.Errorf("%s Description() is empty", c.ID())
			}
			_ = d.RFCRefs()
		}
	}
	// Catalog round-trips through every Check.
	cat := r.Catalog()
	if len(cat) != r.Len() {
		t.Errorf("Catalog len = %d, registry len = %d", len(cat), r.Len())
	}
}
