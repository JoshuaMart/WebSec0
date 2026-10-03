package logsafe

import (
	"strings"
	"testing"
)

func TestSingleLine(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"empty", "", ""},
		{"ordinary", "/api/v1/scan", "/api/v1/scan"},
		{"unicode", "échec TLS", "échec TLS"},
		{"LF", "first\nsecond", `first\nsecond`},
		{"CR", "first\rsecond", `first\rsecond`},
		{"CRLF", "first\r\nsecond", `first\r\nsecond`},
		{"repeated", "\nfirst\r\nsecond\n", `\nfirst\r\nsecond\n`},
		{"existing escapes", `first\nsecond`, `first\nsecond`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SingleLine(tc.input)
			if got != tc.want || strings.ContainsAny(got, "\r\n") {
				t.Fatalf("SingleLine() = %q, want %q", got, tc.want)
			}
			if SingleLine(got) != got {
				t.Fatal("normalization must be idempotent")
			}
		})
	}
}
