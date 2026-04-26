package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log, err := New(&buf, Options{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	log.Info("hello", "key", "value")
	out := buf.String()
	if !strings.Contains(out, `"msg":"hello"`) || !strings.Contains(out, `"key":"value"`) {
		t.Errorf("expected JSON record, got: %s", out)
	}
}

func TestLevelFilter(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log, err := New(&buf, Options{Level: "warn", Format: "text"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	log.Info("dropped")
	log.Warn("kept")
	out := buf.String()
	if strings.Contains(out, "dropped") {
		t.Errorf("info log should be filtered, got: %s", out)
	}
	if !strings.Contains(out, "kept") {
		t.Errorf("warn log missing, got: %s", out)
	}
}

func TestRejectsBadLevel(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, Options{Level: "verbose", Format: "json"}); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestRejectsBadFormat(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, Options{Level: "info", Format: "xml"}); err == nil {
		t.Error("expected error for unknown format")
	}
}
