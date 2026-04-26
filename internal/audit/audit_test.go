package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMaskIPv4(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"192.168.5.42":  "192.168.5.0",
		"10.0.0.1":      "10.0.0.0",
		"203.0.113.255": "203.0.113.0",
		"":              "invalid",
		"not-an-ip":     "invalid",
	}
	for in, want := range cases {
		if got := MaskIP(in); got != want {
			t.Errorf("MaskIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskIPv6KeepsPrefix(t *testing.T) {
	t.Parallel()
	got := MaskIP("2001:db8:1234:5678:9abc:def0:1234:5678")
	if !strings.HasPrefix(got, "2001:db8:1234:5678:") {
		t.Errorf("MaskIPv6 = %q, expected /64 prefix retained", got)
	}
	if strings.Contains(got, "9abc") {
		t.Errorf("MaskIPv6 leaked low-order bits: %q", got)
	}
}

func TestHashHostStableAndShort(t *testing.T) {
	t.Parallel()
	if HashHost("github.com") != HashHost("GitHub.COM") {
		t.Error("HashHost should be case-insensitive")
	}
	if got := HashHost("github.com"); len(got) != 16 {
		t.Errorf("HashHost length = %d, want 16 hex chars", len(got))
	}
}

func TestRecordWritesJSONLine(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewLogger(&buf)
	l.Record(Event{Decision: "accepted", HostHash: "abc", IPMasked: "10.0.0.0", ScanID: "id"})

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Error("output not newline-terminated")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSuffix(out, "\n")), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if got["decision"] != "accepted" || got["scan_id"] != "id" {
		t.Errorf("decoded = %v", got)
	}
}

func TestRecordOnNilWriter(t *testing.T) {
	t.Parallel()
	var l *Logger
	l.Record(Event{Decision: "x"}) // must not panic
	l = NewLogger(nil)
	l.Record(Event{Decision: "x"})
}
