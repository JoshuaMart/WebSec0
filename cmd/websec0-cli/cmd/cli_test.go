package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	// Tests share the package-level `globals` flag struct, so they
	// can't run in parallel against each other.
	var out bytes.Buffer
	root := Root()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.HasPrefix(out.String(), "websec0-cli ") {
		t.Errorf("version output = %q", out.String())
	}
}

func TestCatalogStandalone(t *testing.T) {
	// Tests share the package-level `globals` flag struct, so they
	// can't run in parallel against each other.
	var out bytes.Buffer
	root := Root()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"catalog", "--standalone"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"FAMILY",
		"TLS-CERT-EXPIRED",
		"WELLKNOWN-SECURITY-TXT-MISSING",
		"checks", // tail count line
	} {
		if !strings.Contains(got, want) {
			t.Errorf("catalog output missing %q\n%s", want, got)
		}
	}
}

func TestParseSevList(t *testing.T) {
	t.Parallel()
	got := parseSevList("Critical, high, , medium")
	for _, want := range []string{"critical", "high", "medium"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q", want)
		}
	}
	if _, ok := got[""]; ok {
		t.Errorf("empty entry leaked through")
	}
}
