package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/config"
)

func TestRunProbes_HistoryAddedOnlyWhenRequested(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tgt := targetFor(t, srv)

	cfg := config.Defaults()
	cfg.History.Enabled = true
	cfg.History.Retention = config.Duration(time.Hour)
	s := New(cfg)

	// Direct call: runProbes does not push history. Only Run() does.
	_ = s.runProbes(context.Background(), tgt)
	if len(s.History(0)) != 0 {
		t.Errorf("history should be empty after runProbes alone, got %d", len(s.History(0)))
	}
}

func TestHistory_DisabledReturnsEmpty(t *testing.T) {
	cfg := config.Defaults()
	cfg.History.Enabled = false
	s := New(cfg)
	if got := s.History(10); len(got) != 0 {
		t.Errorf("history disabled: got %d, want 0", len(got))
	}
}

func TestSummarise_CopiesGrades(t *testing.T) {
	// Build a minimal result with both grades set.
	res := stubResultWithGrades("abc", "example.test", "A+", "B")
	e := summarise(res)
	if e.ID != "abc" || e.Host != "example.test" {
		t.Errorf("got %+v", e)
	}
	if string(e.TLSGrade) != "A+" || string(e.HeaderGrade) != "B" {
		t.Errorf("grades not copied: %+v", e)
	}
}
