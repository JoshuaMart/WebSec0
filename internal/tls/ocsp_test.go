package tls

import (
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestParseOCSPStatus_EmptyResponse(t *testing.T) {
	if got := parseOCSPStatus(nil, nil); got != scan.OCSPStatusUnknown {
		t.Errorf("nil: got %q, want unknown", got)
	}
}

func TestParseOCSPStatus_GarbageReturnsParseError(t *testing.T) {
	garbage := []byte{0xde, 0xad, 0xbe, 0xef}
	if got := parseOCSPStatus(garbage, nil); got != scan.OCSPStatusParseError {
		t.Errorf("garbage: got %q, want parse_error", got)
	}
}
