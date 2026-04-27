package memory

import (
	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/storage"
)

// cloneScan returns a shallow-but-safe copy: scalar fields are copied,
// the Findings slice is duplicated, and CompletedAt's pointee is rebased
// onto a fresh time.Time. Evidence/Remediation maps inside findings are
// shared by reference (they are produced once by the check and never
// mutated afterwards).
func cloneScan(s *storage.Scan) *storage.Scan {
	if s == nil {
		return nil
	}
	out := *s
	if s.Findings != nil {
		out.Findings = append([]checks.Finding(nil), s.Findings...)
	}
	if s.CompletedAt != nil {
		t := *s.CompletedAt
		out.CompletedAt = &t
	}
	return &out
}
