package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/history"
	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestHistory_Empty(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{})
	resp, _ := http.Get(srv.URL + "/api/v1/history")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	var got []history.Entry
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("body should be an empty array, not null")
	}
}

func TestHistory_ReturnsEntries(t *testing.T) {
	entries := []history.Entry{
		{ID: "a", Host: "example.test", ScannedAt: time.Now(), TLSGrade: scan.GradeAPlus, HeaderGrade: scan.GradeB},
		{ID: "b", Host: "other.test", ScannedAt: time.Now()},
	}
	srv := newTestServer(t, &fakeScanner{historyList: entries})
	resp, err := http.Get(srv.URL + "/api/v1/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []history.Entry
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].ID != "a" || got[1].ID != "b" {
		t.Errorf("order broken: %v", got)
	}
}

func TestHistory_LimitQuery(t *testing.T) {
	entries := []history.Entry{
		{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}, {ID: "e"},
	}
	srv := newTestServer(t, &fakeScanner{historyList: entries})
	resp, err := http.Get(srv.URL + "/api/v1/history?limit=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []history.Entry
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 2 {
		t.Errorf("limit=2: got %d, want 2", len(got))
	}
}

func TestHistory_RejectsBadLimit(t *testing.T) {
	srv := newTestServer(t, &fakeScanner{})
	for _, q := range []string{"?limit=0", "?limit=-1", "?limit=foo"} {
		resp, _ := http.Get(srv.URL + "/api/v1/history" + q)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status got %d, want 400", q, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestHistory_CapsAtMaxLimit(t *testing.T) {
	entries := make([]history.Entry, 150)
	for i := range entries {
		entries[i] = history.Entry{ID: "x"}
	}
	srv := newTestServer(t, &fakeScanner{historyList: entries})
	resp, err := http.Get(srv.URL + "/api/v1/history?limit=500")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []history.Entry
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != maxHistoryLimit {
		t.Errorf("got %d entries, want max %d", len(got), maxHistoryLimit)
	}
}
