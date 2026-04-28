package wellknown_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/wellknown"
)

// fixtureServer mimics a target's web root with configurable behaviour
// for /.well-known/security.txt and /security.txt.
type fixtureServer struct {
	wellKnownBody []byte
	legacyBody    []byte
	wellKnownCode int // 0 → 404
	legacyCode    int // 0 → 404
}

func (f *fixtureServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/security.txt":
			if len(f.wellKnownBody) == 0 {
				code := f.wellKnownCode
				if code == 0 {
					code = http.StatusNotFound
				}
				http.Error(w, "no", code)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(f.wellKnownBody)
		case "/security.txt":
			if len(f.legacyBody) == 0 {
				code := f.legacyCode
				if code == 0 {
					code = http.StatusNotFound
				}
				http.Error(w, "no", code)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(f.legacyBody)
		default:
			http.NotFound(w, r)
		}
	})
}

func newTarget(t *testing.T, srv *httptest.Server) *checks.Target {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	tgt, err := checks.NewTarget(host, nil)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	tgt.HTTPClient = srv.Client()
	return tgt
}

func runCheck(t *testing.T, c checks.Check, tgt *checks.Target) *checks.Finding {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := c.Run(ctx, tgt)
	if err != nil {
		t.Fatalf("%s: Run err = %v", c.ID(), err)
	}
	if f == nil {
		t.Fatalf("%s: nil finding", c.ID())
	}
	return f
}

func freshRegistry() *checks.Registry {
	r := checks.NewRegistry()
	wellknown.Register(r)
	return r
}

func TestRegisterAddsAllSixChecks(t *testing.T) {
	t.Parallel()
	r := freshRegistry()
	wantIDs := []string{
		wellknown.IDMissing,
		wellknown.IDExpired,
		wellknown.IDNoContact,
		wellknown.IDNoExpires,
		wellknown.IDNotHTTPS,
		wellknown.IDNoSignature,
	}
	for _, id := range wantIDs {
		if _, ok := r.Get(id); !ok {
			t.Errorf("missing %s", id)
		}
	}
	if r.Len() != len(wantIDs) {
		t.Errorf("Len = %d, want %d", r.Len(), len(wantIDs))
	}
}

func TestMissingWhenNoFile(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer((&fixtureServer{}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDMissing), tgt)
	if f.Status != checks.StatusFail {
		t.Errorf("Status = %s, want fail", f.Status)
	}

	// Evidence should expose the structured attempt trail (URL + status
	// per probe), not a nil/null slice — that's what the operator sees on
	// the report page. We don't assert the exact length because HTTPS
	// attempts against the plain-HTTP test server fail fast and may
	// short-circuit, but at least one attempt must be recorded with a URL.
	attempts, ok := f.Evidence["attempts"].([]wellknown.Attempt)
	if !ok {
		t.Fatalf("evidence[attempts] type = %T, want []wellknown.Attempt", f.Evidence["attempts"])
	}
	if len(attempts) == 0 {
		t.Fatal("evidence[attempts] is empty; expected at least one fetch trail entry")
	}
	for i, a := range attempts {
		if a.URL == "" {
			t.Errorf("attempts[%d].URL is empty", i)
		}
		if a.Status == 0 && a.Error == "" {
			t.Errorf("attempts[%d] has neither status nor error: %+v", i, a)
		}
	}
}

func TestPresentWhenWellKnownServed(t *testing.T) {
	t.Parallel()
	body := []byte("Contact: mailto:s@x.com\nExpires: 2099-01-01T00:00:00Z\n")
	srv := httptest.NewServer((&fixtureServer{wellKnownBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDMissing), tgt)
	if f.Status != checks.StatusPass {
		t.Errorf("Status = %s, want pass", f.Status)
	}
}

func TestExpiredFails(t *testing.T) {
	t.Parallel()
	body := []byte("Contact: mailto:s@x.com\nExpires: 2000-01-01T00:00:00Z\n")
	srv := httptest.NewServer((&fixtureServer{wellKnownBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDExpired), tgt)
	if f.Status != checks.StatusFail {
		t.Errorf("Status = %s, want fail (Expires in the past)", f.Status)
	}
}

func TestNoContactFails(t *testing.T) {
	t.Parallel()
	body := []byte("Expires: 2099-01-01T00:00:00Z\n")
	srv := httptest.NewServer((&fixtureServer{wellKnownBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDNoContact), tgt)
	if f.Status != checks.StatusFail {
		t.Errorf("Status = %s, want fail", f.Status)
	}
}

func TestNoExpiresFails(t *testing.T) {
	t.Parallel()
	body := []byte("Contact: mailto:s@x.com\n")
	srv := httptest.NewServer((&fixtureServer{wellKnownBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDNoExpires), tgt)
	if f.Status != checks.StatusFail {
		t.Errorf("Status = %s, want fail", f.Status)
	}
}

func TestNotHTTPSWhenOnlyOverHTTP(t *testing.T) {
	t.Parallel()
	// httptest.NewServer is plain HTTP. The HTTPS attempts will fail
	// (TLS handshake on a non-TLS socket) and the HTTP attempt will
	// succeed → FoundOverHTTPOnly.
	body := []byte("Contact: mailto:s@x.com\nExpires: 2099-01-01T00:00:00Z\n")
	srv := httptest.NewServer((&fixtureServer{wellKnownBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDNotHTTPS), tgt)
	if f.Status != checks.StatusFail {
		t.Errorf("Status = %s, want fail (HTTP-only)", f.Status)
	}
}

func TestNoSignatureWarnsOnUnsignedFile(t *testing.T) {
	t.Parallel()
	body := []byte("Contact: mailto:s@x.com\nExpires: 2099-01-01T00:00:00Z\n")
	srv := httptest.NewServer((&fixtureServer{wellKnownBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDNoSignature), tgt)
	if f.Status != checks.StatusWarn {
		t.Errorf("Status = %s, want warn", f.Status)
	}
}

func TestSignedFilePassesSignatureCheck(t *testing.T) {
	t.Parallel()
	body := []byte(`-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:s@x.com
Expires: 2099-01-01T00:00:00Z
-----BEGIN PGP SIGNATURE-----
fakesignature
-----END PGP SIGNATURE-----
`)
	srv := httptest.NewServer((&fixtureServer{wellKnownBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDNoSignature), tgt)
	if f.Status != checks.StatusPass {
		t.Errorf("Status = %s, want pass", f.Status)
	}
}

func TestLegacyPathStillCounts(t *testing.T) {
	t.Parallel()
	body := []byte("Contact: mailto:s@x.com\nExpires: 2099-01-01T00:00:00Z\n")
	srv := httptest.NewServer((&fixtureServer{legacyBody: body}).handler())
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	f := runCheck(t, getCheck(t, wellknown.IDMissing), tgt)
	if f.Status != checks.StatusPass {
		t.Errorf("Status = %s, want pass (legacy /security.txt)", f.Status)
	}
	ev, _ := f.Evidence["legacy_path"].(bool)
	if !ev {
		t.Errorf("expected evidence.legacy_path=true, got %+v", f.Evidence)
	}
}

func TestFetchIsCachedAcrossChecks(t *testing.T) {
	t.Parallel()
	var hits int
	body := []byte("Contact: mailto:s@x.com\nExpires: 2099-01-01T00:00:00Z\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			hits++
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	tgt := newTarget(t, srv)

	r := freshRegistry()
	for _, id := range []string{
		wellknown.IDMissing, wellknown.IDExpired, wellknown.IDNoContact,
		wellknown.IDNoExpires, wellknown.IDNotHTTPS, wellknown.IDNoSignature,
	} {
		c, _ := r.Get(id)
		_ = runCheck(t, c, tgt)
	}
	if hits > 1 {
		t.Errorf("server hit %d times, want exactly 1 (cache failed)", hits)
	}
}

func getCheck(t *testing.T, id string) checks.Check {
	t.Helper()
	c, ok := freshRegistry().Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	return c
}

// Compile-time sanity: every check value implements both Check and Describer.
var _ = func() error {
	var c checks.Check = struct{ checks.Check }{}
	if _, ok := c.(checks.Describer); !ok {
		return fmt.Errorf("Describer required")
	}
	return nil
}
