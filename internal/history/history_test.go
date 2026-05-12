package history

import (
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestHistory_AddListOrder(t *testing.T) {
	h := New(time.Hour)
	h.Add(Entry{ID: "a", ScannedAt: time.Now()})
	h.Add(Entry{ID: "b", ScannedAt: time.Now()})
	h.Add(Entry{ID: "c", ScannedAt: time.Now()})

	list := h.List(0)
	if len(list) != 3 {
		t.Fatalf("len: got %d, want 3", len(list))
	}
	want := []string{"c", "b", "a"}
	for i, w := range want {
		if list[i].ID != w {
			t.Errorf("list[%d].ID = %s, want %s", i, list[i].ID, w)
		}
	}
}

func TestHistory_ListLimit(t *testing.T) {
	h := New(time.Hour)
	for i := 0; i < 5; i++ {
		h.Add(Entry{ID: "x", ScannedAt: time.Now()})
	}
	if got := h.List(2); len(got) != 2 {
		t.Errorf("limit 2: got %d entries", len(got))
	}
	if got := h.List(0); len(got) != 5 {
		t.Errorf("no limit: got %d entries", len(got))
	}
	if got := h.List(100); len(got) != 5 {
		t.Errorf("limit > size: got %d entries", len(got))
	}
}

func TestHistory_RetentionPurgesOnAdd(t *testing.T) {
	h := New(time.Hour)
	h.Add(Entry{ID: "old", ScannedAt: time.Now().Add(-2 * time.Hour)})
	h.Add(Entry{ID: "new", ScannedAt: time.Now()})

	list := h.List(0)
	if len(list) != 1 || list[0].ID != "new" {
		t.Errorf("old entry should have been purged; got %+v", list)
	}
}

func TestHistory_LazyPurgeOnList(t *testing.T) {
	h := New(time.Hour)
	h.Add(Entry{ID: "freshly-aged", ScannedAt: time.Now()})
	// Fast-forward the clock past retention.
	h.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if got := h.List(0); len(got) != 0 {
		t.Errorf("expected lazy purge on List, got %d entries", len(got))
	}
	if h.Len() != 0 {
		t.Errorf("Len should also purge, got %d", h.Len())
	}
}

func TestHistory_PreservesGrades(t *testing.T) {
	h := New(time.Hour)
	h.Add(Entry{
		ID:          "x",
		Host:        "example.com",
		ScannedAt:   time.Now(),
		TLSGrade:    scan.GradeAPlus,
		HeaderGrade: scan.GradeB,
	})
	got := h.List(1)[0]
	if got.TLSGrade != scan.GradeAPlus || got.HeaderGrade != scan.GradeB {
		t.Errorf("grades not preserved: %+v", got)
	}
}

func TestHistory_ListReturnsCopy(t *testing.T) {
	h := New(time.Hour)
	h.Add(Entry{ID: "a", ScannedAt: time.Now()})
	list := h.List(0)
	list[0].ID = "tampered"
	if h.List(0)[0].ID != "a" {
		t.Error("internal state must not be reachable through the returned slice")
	}
}
