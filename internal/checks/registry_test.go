package checks

import (
	"context"
	"testing"
)

type fakeCheck struct {
	id, fam string
	sev     Severity
}

func (f fakeCheck) ID() string                                         { return f.id }
func (f fakeCheck) Family() Family                                     { return Family(f.fam) }
func (f fakeCheck) DefaultSeverity() Severity                          { return f.sev }
func (f fakeCheck) Run(_ context.Context, _ *Target) (*Finding, error) { return nil, nil }

func TestRegisterAndGet(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	c := fakeCheck{id: "TLS-FOO", fam: "tls", sev: SeverityHigh}
	r.Register(c)

	got, ok := r.Get("TLS-FOO")
	if !ok || got.ID() != "TLS-FOO" {
		t.Errorf("Get returned %v, %v", got, ok)
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d", r.Len())
	}
}

func TestAllSorted(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.Register(fakeCheck{id: "C-2", fam: "f", sev: SeverityLow})
	r.Register(fakeCheck{id: "A-1", fam: "f", sev: SeverityLow})
	r.Register(fakeCheck{id: "B-3", fam: "f", sev: SeverityLow})

	all := r.All()
	want := []string{"A-1", "B-3", "C-2"}
	for i, c := range all {
		if c.ID() != want[i] {
			t.Errorf("All()[%d] = %q, want %q", i, c.ID(), want[i])
		}
	}
}

func TestDuplicatePanics(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.Register(fakeCheck{id: "X", fam: "f", sev: SeverityLow})

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate Register")
		}
	}()
	r.Register(fakeCheck{id: "X", fam: "f", sev: SeverityLow})
}

func TestCatalog(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	r.Register(fakeCheck{id: "Z", fam: "tls", sev: SeverityHigh})
	r.Register(fakeCheck{id: "A", fam: "dns", sev: SeverityLow})

	cat := r.Catalog()
	if len(cat) != 2 {
		t.Fatalf("len = %d", len(cat))
	}
	if cat[0].ID != "A" || cat[1].ID != "Z" {
		t.Errorf("catalog not sorted: %+v", cat)
	}
	if cat[1].Family != FamilyTLS || cat[1].DefaultSeverity != SeverityHigh {
		t.Errorf("metadata mismatch: %+v", cat[1])
	}
}
