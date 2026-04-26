package headers

import "testing"

func TestParseCSPBasic(t *testing.T) {
	t.Parallel()
	csp := ParseCSP("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'")
	if csp == nil {
		t.Fatal("nil CSP")
	}
	if got := csp.Directives["default-src"]; len(got) != 1 || got[0] != "'self'" {
		t.Errorf("default-src = %v", got)
	}
	if got := csp.effective("script-src"); !containsToken(got, "'unsafe-inline'") {
		t.Errorf("script-src effective = %v", got)
	}
	// img-src falls back to default-src
	if got := csp.effective("img-src"); len(got) != 1 || got[0] != "'self'" {
		t.Errorf("img-src fallback = %v", got)
	}
}

func TestParseCSPEmpty(t *testing.T) {
	t.Parallel()
	if csp := ParseCSP(""); csp != nil {
		t.Errorf("ParseCSP(\"\") = %v, want nil", csp)
	}
	if csp := ParseCSP("   ;   "); csp == nil || len(csp.Directives) != 0 {
		t.Errorf("ParseCSP(whitespace) = %+v", csp)
	}
}

func TestParseCSPDuplicateKeepsFirst(t *testing.T) {
	t.Parallel()
	csp := ParseCSP("script-src 'self'; script-src 'unsafe-eval'")
	if got := csp.Directives["script-src"]; len(got) != 1 || got[0] != "'self'" {
		t.Errorf("first directive should win, got %v", got)
	}
}
