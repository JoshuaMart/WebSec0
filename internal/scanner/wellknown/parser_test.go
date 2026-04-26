package wellknown

import (
	"strings"
	"testing"
	"time"
)

func TestParseFullDocument(t *testing.T) {
	t.Parallel()
	in := `# Comment
Contact: mailto:security@example.com
Contact: https://example.com/security
Expires: 2030-01-01T00:00:00Z
Encryption: https://example.com/pgp.asc
Acknowledgments: https://example.com/hall-of-fame
Preferred-Languages: en, fr, de
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy
Hiring: https://example.com/jobs
CSAF: https://example.com/csaf.json
`
	got, err := ParseSecurityTxt([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Contact) != 2 {
		t.Errorf("Contact = %v", got.Contact)
	}
	if got.Expires == nil || got.Expires.Year() != 2030 {
		t.Errorf("Expires = %v", got.Expires)
	}
	if want := []string{"en", "fr", "de"}; !equalSlice(got.PreferredLanguages, want) {
		t.Errorf("Preferred-Languages = %v", got.PreferredLanguages)
	}
	if len(got.Encryption) != 1 || len(got.Canonical) != 1 || len(got.Policy) != 1 || len(got.Hiring) != 1 || len(got.CSAF) != 1 {
		t.Errorf("missing single-entry fields: %+v", got)
	}
	if len(got.ParseWarnings) != 0 {
		t.Errorf("unexpected warnings: %v", got.ParseWarnings)
	}
	if got.Signed {
		t.Errorf("plain document reported as signed")
	}
}

func TestParseSignedDocument(t *testing.T) {
	t.Parallel()
	in := `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:sec@example.com
Expires: 2099-12-31T23:59:59Z
-----BEGIN PGP SIGNATURE-----
iQEcBAEBCAAGBQJ...fake signature
-----END PGP SIGNATURE-----
`
	got, err := ParseSecurityTxt([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !got.Signed {
		t.Error("Signed = false")
	}
	if len(got.Contact) != 1 || got.Contact[0] != "mailto:sec@example.com" {
		t.Errorf("Contact = %v", got.Contact)
	}
	if got.Expires == nil {
		t.Error("Expires not parsed inside signed body")
	}
}

func TestParseEmptyRejects(t *testing.T) {
	t.Parallel()
	if _, err := ParseSecurityTxt([]byte("   \n\n")); err == nil {
		t.Error("expected error for empty document")
	}
}

func TestParseExpiredDocument(t *testing.T) {
	t.Parallel()
	in := "Contact: mailto:x@example.com\nExpires: 2000-01-01T00:00:00Z\n"
	got, err := ParseSecurityTxt([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Expires == nil || got.Expires.After(time.Now()) {
		t.Errorf("Expires = %v, want past", got.Expires)
	}
}

func TestParseWarnsOnAnomalies(t *testing.T) {
	t.Parallel()
	in := strings.Join([]string{
		"Contact: mailto:a@b.c",
		"Garbage line without colon",
		"Expires: not-a-date",
		"Expires: 2030-01-01T00:00:00Z",
		"Expires: 2031-01-01T00:00:00Z", // duplicate
		"Unknown-Field: foo",
		"",
	}, "\n")
	got, err := ParseSecurityTxt([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.ParseWarnings) < 4 {
		t.Errorf("warnings = %v (want ≥ 4)", got.ParseWarnings)
	}
	if got.Expires == nil || got.Expires.Year() != 2030 {
		t.Errorf("first valid Expires should win, got %v", got.Expires)
	}
}

func TestIsSecureURL(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"https://example.com/x":       true,
		"HTTPS://example.com/x":       true,
		"http://example.com/x":        false,
		"mailto:security@example.com": true, // not a scheme we flag
		"":                            false,
		"://broken":                   false,
	}
	for in, want := range cases {
		if got := IsSecureURL(in); got != want {
			t.Errorf("IsSecureURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
