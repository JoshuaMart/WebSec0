package tls

import (
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// TestRegister_AllChecksHaveValidMetadata mirrors the email-package
// generic metadata test (see scanner/email/metadata_test.go for
// rationale).
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
		// TLS family check IDs may start with TLS- or SRI- (mixed history)
		// but must remain in the TLS family.
		if !strings.HasPrefix(c.ID(), "TLS-") {
			t.Errorf("%s does not start with TLS-", c.ID())
		}
		if c.Family() != checks.FamilyTLS {
			t.Errorf("%s family = %s, want tls", c.ID(), c.Family())
		}
		switch c.DefaultSeverity() {
		case checks.SeverityInfo, checks.SeverityLow,
			checks.SeverityMedium, checks.SeverityHigh, checks.SeverityCritical:
		default:
			t.Errorf("%s severity = %q, not canonical", c.ID(), c.DefaultSeverity())
		}
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
	if len(r.Catalog()) != r.Len() {
		t.Errorf("Catalog/Register count mismatch")
	}
}
