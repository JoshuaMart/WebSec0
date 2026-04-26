package version

import "testing"

func TestGetReturnsCurrentValues(t *testing.T) {
	t.Parallel()
	got := Get()
	if got.Version != Version || got.Commit != Commit || got.BuildDate != BuildDate {
		t.Fatalf("Get() = %+v, want fields equal to package vars", got)
	}
}
