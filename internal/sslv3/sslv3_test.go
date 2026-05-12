package sslv3

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty", nil, false},
		{"too short", []byte{0x16, 0x03}, false},
		{"sslv3 server-hello", []byte{0x16, 0x03, 0x00, 0x00, 0x42}, true},
		{"tls 1.0 handshake", []byte{0x16, 0x03, 0x01, 0x00, 0x42}, false},
		{"tls 1.2 handshake", []byte{0x16, 0x03, 0x03, 0x00, 0x42}, false},
		{"tls alert", []byte{0x15, 0x03, 0x00, 0x00, 0x02}, false},
		{"sslv2 framing", []byte{0x80, 0x14, 0x04, 0x00, 0x02}, false},
	}
	for _, c := range cases {
		if got := classify(c.in); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBuildClientHello_Length(t *testing.T) {
	h, err := buildClientHello()
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 54 {
		t.Errorf("len: got %d, want 54", len(h))
	}
	// Record header signals SSLv3 framing.
	if h[0] != 0x16 || h[1] != 0x03 || h[2] != 0x00 {
		t.Errorf("record header: got % x, want 16 03 00", h[:3])
	}
}

func cannedServer(t *testing.T, reply []byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(reply)
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func targetForListener(t *testing.T, ln net.Listener) *safehttp.Target {
	t.Helper()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	tgt, err := safehttp.NewTarget("https", "example.test", p, netip.MustParseAddr(host))
	if err != nil {
		t.Fatal(err)
	}
	return tgt
}

func TestProbe_CannedSSLv3Server(t *testing.T) {
	ln := cannedServer(t, []byte{0x16, 0x03, 0x00, 0x00, 0x42, 0x02, 0x00, 0x00, 0x3e})
	tgt := targetForListener(t, ln)
	if !Probe(context.Background(), tgt, time.Second) {
		t.Error("expected supported against canned SSLv3 server-hello")
	}
}

func TestProbe_ModernTLSServerAlerts(t *testing.T) {
	// httptest.NewTLSServer rejects an SSLv3 client and likely returns an alert.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	tgt, err := safehttp.NewTarget("https", "example.test", port, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if Probe(context.Background(), tgt, time.Second) {
		t.Error("expected not supported against modern TLS server")
	}
}

func TestProbe_CannedTLS12Response(t *testing.T) {
	ln := cannedServer(t, []byte{0x16, 0x03, 0x03, 0x00, 0x42})
	tgt := targetForListener(t, ln)
	if Probe(context.Background(), tgt, time.Second) {
		t.Error("server replied with TLS 1.2 framing — must be not supported")
	}
}
