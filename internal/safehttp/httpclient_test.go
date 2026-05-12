package safehttp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// targetFor builds a Target whose IP is the loopback that httptest binds.
// We deliberately use a host string that has no DNS record — proving that
// the pinned IP path bypasses name resolution.
func targetFor(t *testing.T, srvURL, host string) *Target {
	t.Helper()
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	return &Target{
		Scheme:   "https",
		Host:     host,
		Port:     port,
		IP:       ip,
		addrPort: netip.AddrPortFrom(ip, uint16(port)),
	}
}

func TestNewClient_PinnedDialBypassesDNS(t *testing.T) {
	body := "hello-from-pinned\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	// "rebinder.invalid" has no DNS record; the request must still succeed
	// because the client dials Target.IP (127.0.0.1), not the URL host.
	tgt := targetFor(t, srv.URL, "rebinder.invalid")
	c := NewClient(ClientOpts{Target: tgt, Timeout: 3 * time.Second})

	resp, err := c.Get(tgt.URL("/"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Errorf("body: got %q, want %q", got, body)
	}
}

func TestNewClient_SetsSNIAndHostHeader(t *testing.T) {
	var seenHost string
	var seenSNI string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		fmt.Fprint(w, "ok")
	}))
	srv.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			seenSNI = hello.ServerName
			return nil, nil // fall back to default
		},
	}
	srv.StartTLS()
	defer srv.Close()

	tgt := targetFor(t, srv.URL, "example.test")
	c := NewClient(ClientOpts{Target: tgt, Timeout: 3 * time.Second})

	resp, err := c.Get(tgt.URL("/"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if seenSNI != "example.test" {
		t.Errorf("SNI: got %q, want example.test", seenSNI)
	}
	// Host header may include port when non-default.
	if seenHost != tgt.HostPort() {
		t.Errorf("Host header: got %q, want %q", seenHost, tgt.HostPort())
	}
}

func TestNewClient_BodyCapTrips(t *testing.T) {
	payload := bytes.Repeat([]byte("A"), 4096)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv.URL, "example.test")
	c := NewClient(ClientOpts{
		Target:       tgt,
		Timeout:      3 * time.Second,
		MaxBodyBytes: 1024,
	})

	resp, err := c.Get(tgt.URL("/"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("expected ErrBodyTooLarge, got %v (read %d bytes)", err, len(got))
	}
	if len(got) != 1024 {
		t.Errorf("read %d bytes, want exactly 1024 before the cap trips", len(got))
	}
}

func TestNewClient_RedirectOffHostRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "https://attacker.invalid/done", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv.URL, "example.test")
	c := NewClient(ClientOpts{
		Target:          tgt,
		Timeout:         3 * time.Second,
		FollowRedirects: true,
		MaxRedirects:    3,
	})

	resp, err := c.Get(tgt.URL("/start"))
	if !errors.Is(err, ErrOffHostRedirect) {
		t.Fatalf("expected ErrOffHostRedirect, got %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusFound {
		t.Errorf("expected the 302 response to be returned alongside the error")
	}
	if resp != nil {
		resp.Body.Close()
	}
}

func TestNewClient_RedirectDisabledReturnsResponseAsIs(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv.URL, "example.test")
	c := NewClient(ClientOpts{Target: tgt, Timeout: 3 * time.Second, FollowRedirects: false})

	resp, err := c.Get(tgt.URL("/start"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status: got %d, want 302", resp.StatusCode)
	}
}
