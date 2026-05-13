package custom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

func makeTarget(t *testing.T, srv *httptest.Server) *safehttp.Target {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	tgt, err := safehttp.NewTarget("https", "example.test", port, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return tgt
}

func TestParseSecurityTxt(t *testing.T) {
	body := `# A comment
Contact: mailto:security@example.com
Contact: https://example.com/security
Expires: 2030-01-01T00:00:00Z
Encryption: https://example.com/pgp.txt
`
	got := parseSecurityTxt(body)
	if len(got.Contacts) != 2 {
		t.Errorf("contacts: got %d, want 2", len(got.Contacts))
	}
	if got.Expires.Year() != 2030 {
		t.Errorf("expires: got %s, want 2030", got.Expires)
	}
	if got.Signed {
		t.Error("unsigned body should not flag Signed")
	}
}

func TestParseSecurityTxt_PGPSigned(t *testing.T) {
	body := `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:sec@example.com
Expires: 2030-01-01T00:00:00Z
-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`
	got := parseSecurityTxt(body)
	if !got.Signed {
		t.Error("Signed should be true for PGP-wrapped body")
	}
	if len(got.Contacts) != 1 {
		t.Errorf("contacts: got %d, want 1", len(got.Contacts))
	}
}

func TestParseSecurityTxt_ExpiresLowercaseZ(t *testing.T) {
	// RFC 3339 §5.6 allows lowercase 't' and 'z'; github.com's file
	// uses `Expires: 2026-06-11T19:09:02z`.
	body := "Contact: mailto:x@example.com\nExpires: 2026-06-11T19:09:02z\n"
	got := parseSecurityTxt(body)
	if got.Expires.IsZero() {
		t.Fatal("Expires with lowercase z should parse, got zero")
	}
	if got.Expires.Year() != 2026 || got.Expires.Month() != 6 || got.Expires.Day() != 11 {
		t.Errorf("expires: got %s, want 2026-06-11", got.Expires)
	}
}

func TestParseSecurityTxt_ExpiresFractional(t *testing.T) {
	body := "Contact: mailto:x@example.com\nExpires: 2030-01-01T00:00:00.500Z\n"
	got := parseSecurityTxt(body)
	if got.Expires.Year() != 2030 {
		t.Errorf("fractional Expires should parse, got %s", got.Expires)
	}
}

func TestParseSecurityTxt_MalformedExpires(t *testing.T) {
	body := `Contact: mailto:x@example.com
Expires: not-a-date
`
	got := parseSecurityTxt(body)
	if !got.Expires.IsZero() {
		t.Errorf("malformed Expires should be zero, got %s", got.Expires)
	}
}

func TestSecurityTxt_Pass(t *testing.T) {
	body := "Contact: mailto:x@example.com\nExpires: 2099-01-01T00:00:00Z\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	f := SecurityTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusPass {
		t.Errorf("status: got %s, want pass", f.Status)
	}
	var d securityTxtDetails
	_ = json.Unmarshal(f.Details, &d)
	if d.ContactCount != 1 {
		t.Errorf("ContactCount: got %d, want 1", d.ContactCount)
	}
	if !d.RFC9116Compliant {
		t.Error("RFC9116Compliant should be true")
	}
}

func TestSecurityTxt_Fail_404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	f := SecurityTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusFail {
		t.Errorf("404: got %s, want fail", f.Status)
	}
}

// TestSecurityTxt_Fail_HTMLContentType — RFC 9116 §2.4 requires
// text/plain; an HTML SPA fallback served on /.well-known/security.txt
// means the file is missing, not that we should try to parse the HTML.
func TestSecurityTxt_Fail_HTMLContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>landing</body></html>"))
	}))
	defer srv.Close()
	f := SecurityTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusFail {
		t.Errorf("HTML response: got %s, want fail", f.Status)
	}
	var d securityTxtDetails
	_ = json.Unmarshal(f.Details, &d)
	if d.Note == "" {
		t.Errorf("HTML response should set a Note explaining the situation")
	}
}

func TestSecurityTxt_Warn_Expired(t *testing.T) {
	body := "Contact: mailto:x@example.com\nExpires: " + time.Now().Add(-time.Hour).Format(time.RFC3339) + "\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f := SecurityTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusWarn {
		t.Errorf("expired: got %s, want warn", f.Status)
	}
}

func TestSecurityTxt_Warn_MissingExpires(t *testing.T) {
	body := "Contact: mailto:x@example.com\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f := SecurityTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusWarn {
		t.Errorf("missing Expires: got %s, want warn", f.Status)
	}
}

func TestSecurityTxt_Fail_NoContacts(t *testing.T) {
	body := "Expires: 2099-01-01T00:00:00Z\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f := SecurityTxt{}.Run(context.Background(), makeTarget(t, srv))
	if f.Status != scan.StatusFail {
		t.Errorf("no Contact: got %s, want fail", f.Status)
	}
}
