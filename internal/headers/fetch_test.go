package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"

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

func TestProbe_HappyPath(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Add("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Strict")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report, err := Probe(context.Background(), makeTarget(t, srv))
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]scan.Status{
		"strict-transport-security": scan.StatusPass,
		"content-security-policy":   scan.StatusPass,
		"x-frame-options":           scan.StatusPass,
		"x-content-type-options":    scan.StatusPass,
		"referrer-policy":           scan.StatusPass,
		"permissions-policy":        scan.StatusPass,
	}
	for name, w := range want {
		if got := report.Core[name].Status; got != w {
			t.Errorf("%s: got %s, want %s", name, got, w)
		}
	}
	if report.Additional.CrossOriginOpenerPolicy == nil ||
		report.Additional.CrossOriginOpenerPolicy.Status != scan.StatusPass {
		t.Error("COOP same-origin should pass")
	}
	if len(report.Additional.SetCookie) != 1 || report.Additional.SetCookie[0].Status != scan.StatusPass {
		t.Errorf("session cookie should pass, got %+v", report.Additional.SetCookie)
	}
}

func TestProbe_EmptyResponse_AllCoreFail(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report, err := Probe(context.Background(), makeTarget(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range CoreHeaderNames {
		if report.Core[name].Status != scan.StatusFail {
			t.Errorf("%s: expected fail, got %s", name, report.Core[name].Status)
		}
	}
}

func TestFetch_CapturesMultipleSetCookie(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; Secure")
		w.Header().Add("Set-Cookie", "b=2; Secure")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, err := Fetch(context.Background(), makeTarget(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(h.Values("Set-Cookie")); got != 2 {
		t.Errorf("expected 2 Set-Cookie values, got %d", got)
	}
}
