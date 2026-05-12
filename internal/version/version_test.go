package version

import (
	"strings"
	"testing"
)

func TestString_IncludesAllFields(t *testing.T) {
	prevV, prevC, prevD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = prevV, prevC, prevD })

	Version = "v1.2.3"
	Commit = "abc123"
	Date = "2026-05-12T00:00:00Z"

	got := String()
	for _, want := range []string{"v1.2.3", "abc123", "2026-05-12T00:00:00Z", "websec0"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, must contain %q", got, want)
		}
	}
}

func TestString_DefaultValues(t *testing.T) {
	if !strings.Contains(String(), "dev") {
		t.Error("default Version should be \"dev\"")
	}
}
