package scoring_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
	"github.com/JoshuaMart/websec0/internal/scoring"
)

func TestTLSReferenceFixtures(t *testing.T) {
	for _, name := range []string{
		"modern_hsts",
		"modern_no_hsts",
		"legacy_weak",
		"untrusted_legacy",
		"partial_blocked",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join("testdata", "tls", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Report   scan.Result `json:"report"`
				Expected struct {
					Scores scan.TLSScores `json:"scores"`
					Grade  scan.Grade     `json:"grade"`
				} `json:"expected"`
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&fixture); err != nil {
				t.Fatal(err)
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				t.Fatalf("expected one JSON object, got trailing data: %v", err)
			}
			if fixture.Report.TLS == nil || !fixture.Expected.Grade.IsValid() {
				t.Fatal("fixture must provide TLS observations and a valid expected grade")
			}

			scores, grade := scoring.TLSFinal(fixture.Report.TLS, fixture.Report.Headers)
			if scores != fixture.Expected.Scores {
				t.Errorf("scores: got %+v, want %+v", scores, fixture.Expected.Scores)
			}
			if grade != fixture.Expected.Grade {
				t.Errorf("grade: got %s, want %s", grade, fixture.Expected.Grade)
			}
		})
	}
}
