package custom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAll_StableOrder(t *testing.T) {
	first := All()
	second := All()
	if len(first) != len(second) {
		t.Fatal("All() length differs across calls")
	}
	for i := range first {
		if first[i].ID() != second[i].ID() {
			t.Errorf("All()[%d].ID() differs across calls", i)
		}
	}
}

func TestRunAll_AllFindingsReturned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	out := RunAll(context.Background(), makeTarget(t, srv))
	if len(out) != len(All()) {
		t.Errorf("got %d findings, want %d (one per registered check)", len(out), len(All()))
	}
	seen := map[string]bool{}
	for _, f := range out {
		seen[f.ID] = true
	}
	for _, c := range All() {
		if !seen[c.ID()] {
			t.Errorf("missing finding for %s", c.ID())
		}
	}
}
