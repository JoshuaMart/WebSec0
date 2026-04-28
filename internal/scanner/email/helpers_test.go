package email

import (
	"errors"
	"testing"

	"github.com/JoshuaMart/websec0/internal/checks"
)

// Helpers under test produce uniform Finding shapes for the family —
// keep them small, table-friendly assertions.

func TestEmailHelpers_Finding(t *testing.T) {
	t.Run("errFinding", func(t *testing.T) {
		f := errFinding("EMAIL-X", checks.SeverityHigh, errors.New("boom"))
		if f.Status != checks.StatusError || f.Family != checks.FamilyEmail || f.ID != "EMAIL-X" {
			t.Errorf("errFinding shape: %+v", f)
		}
		if f.Description != "boom" {
			t.Errorf("Description = %q, want boom", f.Description)
		}
	})
	t.Run("skipped", func(t *testing.T) {
		f := skipped("EMAIL-X", checks.SeverityLow, "no MX")
		if f.Status != checks.StatusSkipped || f.Title != "skipped: no MX" {
			t.Errorf("skipped shape: %+v", f)
		}
	})
	t.Run("warn", func(t *testing.T) {
		f := warn("EMAIL-X", checks.SeverityMedium, "drift", "details", map[string]any{"k": "v"})
		if f.Status != checks.StatusWarn || f.Title != "drift" || f.Evidence["k"] != "v" {
			t.Errorf("warn shape: %+v", f)
		}
	})
}
