package email

import "testing"

func TestParseSPFBasic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw       string
		hasAll    bool
		qualifier byte
		nilOK     bool
	}{
		{"v=spf1 include:_spf.google.com ~all", true, '~', false},
		{"v=spf1 -all", true, '-', false},
		{"v=spf1 +all", true, '+', false},
		{"v=spf1 a mx", false, 0, false},
		{"v=spf1 ip4:1.2.3.4", false, 0, false},
		{"", false, 0, true},
	}
	for _, c := range cases {
		got, _ := ParseSPF(c.raw)
		if c.nilOK {
			if got != nil {
				t.Errorf("ParseSPF(%q) = %+v, want nil", c.raw, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("ParseSPF(%q) = nil", c.raw)
			continue
		}
		if got.HasAll != c.hasAll {
			t.Errorf("ParseSPF(%q).HasAll = %v, want %v", c.raw, got.HasAll, c.hasAll)
		}
		if got.AllQualifier != c.qualifier {
			t.Errorf("ParseSPF(%q).AllQualifier = %q, want %q", c.raw, got.AllQualifier, c.qualifier)
		}
	}
}

func TestParseSPFInvalidPrefix(t *testing.T) {
	t.Parallel()
	_, errs := ParseSPF("v=spf2 -all")
	if len(errs) == 0 {
		t.Error("expected error for non-spf1 prefix")
	}
}

func TestParseSPFDetectsPTR(t *testing.T) {
	t.Parallel()
	got, _ := ParseSPF("v=spf1 ptr -all")
	if got == nil {
		t.Fatal("nil")
	}
	hasPTR := false
	for _, t := range got.Terms {
		if t.Name == "ptr" {
			hasPTR = true
		}
	}
	if !hasPTR {
		t.Error("did not detect ptr mechanism")
	}
}

func TestParseDKIM(t *testing.T) {
	t.Parallel()
	d := ParseDKIM("v=DKIM1; k=rsa; t=y; h=sha1:sha256; p=")
	if d == nil {
		t.Fatal("nil")
	}
	if !d.TestMode {
		t.Error("TestMode = false")
	}
	if !d.Revoked {
		t.Error("Revoked = false (p empty)")
	}
	if len(d.Hashes) != 2 || d.Hashes[0] != "sha1" {
		t.Errorf("Hashes = %v", d.Hashes)
	}
}

func TestParseDKIMDefaults(t *testing.T) {
	t.Parallel()
	d := ParseDKIM("v=DKIM1; p=ABC")
	if d == nil {
		t.Fatal("nil")
	}
	if len(d.Hashes) != 1 || d.Hashes[0] != "sha256" {
		t.Errorf("default hash = %v, want [sha256]", d.Hashes)
	}
	if d.TestMode {
		t.Error("TestMode true with no t= tag")
	}
}

func TestParseDMARC(t *testing.T) {
	t.Parallel()
	d := ParseDMARC("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100")
	if d == nil {
		t.Fatal("nil")
	}
	if len(d.Errors) != 0 {
		t.Errorf("unexpected errors: %v", d.Errors)
	}
	if d.Tags["p"] != "reject" || d.Tags["rua"] != "mailto:dmarc@example.com" {
		t.Errorf("tags = %v", d.Tags)
	}
}

func TestParseDMARCMissingP(t *testing.T) {
	t.Parallel()
	d := ParseDMARC("v=DMARC1; sp=quarantine")
	if d == nil || len(d.Errors) == 0 {
		t.Error("expected error for missing p= tag")
	}
}

func TestParseMTASTSPolicy(t *testing.T) {
	t.Parallel()
	body := "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 604800\n"
	p := ParseMTASTSPolicy(body)
	if p == nil {
		t.Fatal("nil")
	}
	if p.Mode != "enforce" || p.MaxAge != 604800 || len(p.MX) != 2 {
		t.Errorf("policy = %+v", p)
	}
}
