package cookies_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/cookies"
)

// schemeRewrite mirrors the helper from the headers package: httptest is
// HTTP-only, so we downgrade outbound https:// requests at the transport.
type schemeRewrite struct{ base http.RoundTripper }

func (s *schemeRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		clone := *req
		u := *req.URL
		u.Scheme = "http"
		clone.URL = &u
		req = &clone
	}
	rt := s.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(req)
}

// newServer spins up an HTTP fixture that emits the given Set-Cookie
// values verbatim (one entry per Set-Cookie header).
func newServer(t *testing.T, setCookies ...string) *checks.Target {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for _, sc := range setCookies {
			w.Header().Add("Set-Cookie", sc)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	tgt.HTTPClient = srv.Client()
	tgt.HTTPClient.Transport = &schemeRewrite{base: srv.Client().Transport}
	return tgt
}

func runCheck(t *testing.T, id string, tgt *checks.Target) *checks.Finding {
	t.Helper()
	r := checks.NewRegistry()
	cookies.Register(r)
	c, ok := r.Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := c.Run(ctx, tgt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return f
}

func TestRegisterAddsAllCookieChecks(t *testing.T) {
	t.Parallel()
	r := checks.NewRegistry()
	cookies.Register(r)
	for _, id := range []string{
		cookies.IDSecureMissing, cookies.IDHTTPOnlyMissingSession,
		cookies.IDSameSiteMissing, cookies.IDSameSiteNoneNotSecure,
		cookies.IDNoSecurityFlags, cookies.IDPrefixSecureMissing,
		cookies.IDPrefixHostMissing,
	} {
		if _, ok := r.Get(id); !ok {
			t.Errorf("missing %s", id)
		}
	}
}

func TestIsSessionCookieHeuristic(t *testing.T) {
	t.Parallel()
	yes := []string{
		"sessionid", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
		"connect.sid", "_session_id", "auth_token", "csrf_token",
		"my_session", "userSessId", "__Secure-sessionid", "__Host-session",
	}
	no := []string{"foo", "tracking_pixel", "cart_count"}
	for _, n := range yes {
		if !cookies.IsSessionCookie(n) {
			t.Errorf("IsSessionCookie(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if cookies.IsSessionCookie(n) {
			t.Errorf("IsSessionCookie(%q) = true, want false", n)
		}
	}
}

func TestNoCookiesSkipsAll(t *testing.T) {
	t.Parallel()
	tgt := newServer(t)
	for _, id := range []string{
		cookies.IDSecureMissing, cookies.IDSameSiteMissing,
		cookies.IDNoSecurityFlags,
	} {
		if g := runCheck(t, id, tgt); g.Status != checks.StatusSkipped {
			t.Errorf("%s = %s, want skipped (no cookies)", id, g.Status)
		}
	}
}

func TestSecureMissingDetected(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "sid=abc; Path=/")
	if g := runCheck(t, cookies.IDSecureMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("SECURE-MISSING = %s, want fail", g.Status)
	}
}

func TestSecurePresentPasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	if g := runCheck(t, cookies.IDSecureMissing, tgt); g.Status != checks.StatusPass {
		t.Errorf("SECURE-MISSING with Secure = %s, want pass", g.Status)
	}
}

func TestHTTPOnlyMissingForSessionCookie(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "sessionid=abc; Path=/; Secure; SameSite=Lax")
	if g := runCheck(t, cookies.IDHTTPOnlyMissingSession, tgt); g.Status != checks.StatusFail {
		t.Errorf("HTTPONLY-MISSING-SESSION = %s, want fail", g.Status)
	}
}

func TestHTTPOnlySkippedForNonSessionCookies(t *testing.T) {
	t.Parallel()
	// no name matches the session heuristic → check skips
	tgt := newServer(t, "tracking=abc; Path=/; Secure")
	if g := runCheck(t, cookies.IDHTTPOnlyMissingSession, tgt); g.Status != checks.StatusSkipped {
		t.Errorf("HTTPONLY-MISSING-SESSION on non-session = %s, want skipped", g.Status)
	}
}

func TestSameSiteMissing(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "sid=abc; Path=/; Secure; HttpOnly")
	if g := runCheck(t, cookies.IDSameSiteMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("SAMESITE-MISSING = %s, want fail", g.Status)
	}
}

func TestSameSiteNoneWithoutSecureFails(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "tracker=abc; Path=/; SameSite=None")
	if g := runCheck(t, cookies.IDSameSiteNoneNotSecure, tgt); g.Status != checks.StatusFail {
		t.Errorf("SAMESITE-NONE-WITHOUT-SECURE = %s, want fail", g.Status)
	}
}

func TestSameSiteNoneWithSecurePasses(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "tracker=abc; Path=/; Secure; SameSite=None")
	if g := runCheck(t, cookies.IDSameSiteNoneNotSecure, tgt); g.Status != checks.StatusPass {
		t.Errorf("SAMESITE-NONE+Secure = %s, want pass", g.Status)
	}
}

func TestSameSiteNoneCheckSkipsWithoutSameSiteNone(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "tracker=abc; Path=/; Secure; SameSite=Lax")
	if g := runCheck(t, cookies.IDSameSiteNoneNotSecure, tgt); g.Status != checks.StatusSkipped {
		t.Errorf("SAMESITE-NONE check without any None cookie = %s, want skipped", g.Status)
	}
}

func TestNoSecurityFlagsAtAll(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "tracker=abc; Path=/")
	if g := runCheck(t, cookies.IDNoSecurityFlags, tgt); g.Status != checks.StatusFail {
		t.Errorf("NO-SECURITY-FLAGS = %s, want fail", g.Status)
	}
}

func TestPrefixSecureFailsOnPlainSession(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	if g := runCheck(t, cookies.IDPrefixSecureMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("PREFIX-SECURE = %s, want fail", g.Status)
	}
}

func TestPrefixSecurePassesOnPrefixedSession(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "__Secure-sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	if g := runCheck(t, cookies.IDPrefixSecureMissing, tgt); g.Status != checks.StatusPass {
		t.Errorf("PREFIX-SECURE on __Secure- = %s, want pass", g.Status)
	}
}

func TestPrefixHostStrictlyRequiresHostPrefix(t *testing.T) {
	t.Parallel()
	tgt := newServer(t, "__Secure-sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	if g := runCheck(t, cookies.IDPrefixHostMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("PREFIX-HOST on __Secure- = %s, want fail (only __Host- passes)", g.Status)
	}
	tgt2 := newServer(t, "__Host-sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	if g := runCheck(t, cookies.IDPrefixHostMissing, tgt2); g.Status != checks.StatusPass {
		t.Errorf("PREFIX-HOST on __Host- = %s, want pass", g.Status)
	}
}
