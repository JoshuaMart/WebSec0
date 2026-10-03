package custom

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestFetchText_ReadErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		length   int
		capBytes int64
		wantErr  error
	}{
		{"exact limit", "abcd", 4, 4, nil},
		{"over limit", "abcde", 5, 4, safehttp.ErrBodyTooLarge},
		{"interrupted body", "abcd", 10, 20, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(tc.length))
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			_, status, _, err := fetchText(context.Background(), makeTarget(t, srv), "/", tc.capBytes)
			if !errors.Is(err, tc.wantErr) || status != http.StatusOK {
				t.Fatalf("status=%d err=%v, want %v", status, err, tc.wantErr)
			}
		})
	}
}

func TestChecks_IncompleteResponsesAreNotPassed(t *testing.T) {
	for _, check := range All() {
		for _, oversized := range []bool{false, true} {
			t.Run(check.ID()+"/oversized="+strconv.FormatBool(oversized), func(t *testing.T) {
				body := "Contact: mailto:security@example.test\nExpires: 2099-01-01T00:00:00Z\nUser-agent: *\n"
				if oversized {
					body += strings.Repeat("# filler\n", robotsTxtMaxBytes)
				}
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/plain")
					length := len(body)
					if !oversized {
						length += 100
					}
					w.Header().Set("Content-Length", strconv.Itoa(length))
					_, _ = io.WriteString(w, body)
				}))
				defer srv.Close()
				finding := check.Run(context.Background(), makeTarget(t, srv))
				if finding.Status != scan.StatusInfo {
					t.Fatalf("status=%s", finding.Status)
				}
				var details map[string]any
				if err := json.Unmarshal(finding.Details, &details); err != nil {
					t.Fatal(err)
				}
				note, _ := details["note"].(string)
				if !strings.Contains(note, "Incomplete response") {
					t.Fatalf("missing read error: %s", finding.Details)
				}
			})
		}
	}
}
