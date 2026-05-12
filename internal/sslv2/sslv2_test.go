package sslv2

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
		{"too short", []byte{0x80}, false},
		{"tls handshake framing", []byte{0x16, 0x03, 0x03, 0x00, 0x10}, false},
		{"tls alert framing", []byte{0x15, 0x03, 0x03, 0x00, 0x02}, false},
		{"sslv2 server-hello 2-byte len", []byte{0x80, 0x14, 0x04, 0x00, 0x02}, true},
		{"sslv2 server-hello 3-byte len", []byte{0x40, 0x00, 0x14, 0x04, 0x00}, true},
		{"sslv2 framing but msg type 0x01", []byte{0x80, 0x14, 0x01, 0x00, 0x02}, false},
		{"random garbage", []byte{0xde, 0xad, 0xbe, 0xef, 0x00}, false},
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
	// Fixed structure: 2 (len) + 1 (type) + 2 (ver) + 2 (cipher_len) + 2 (sid_len)
	// + 2 (challenge_len) + 21 (specs) + 16 (challenge) = 48 bytes.
	if len(h) != 48 {
		t.Errorf("len: got %d, want 48", len(h))
	}
	if h[0] != 0x80 || h[1] != 0x2e || h[2] != 0x01 {
		t.Errorf("prefix: got % x, want 80 2e 01", h[:3])
	}
}

// targetForListener wraps a net.Listener into a safehttp.Target.
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

// cannedServer replies with the given bytes after reading any client data.
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
		// Drain the client hello (best-effort, short read window).
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(reply)
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestProbe_CannedSSLv2Server(t *testing.T) {
	ln := cannedServer(t, []byte{0x80, 0x14, 0x04, 0x00, 0x02, 0x00, 0x01})
	tgt := targetForListener(t, ln)
	if !Probe(context.Background(), tgt, time.Second) {
		t.Error("expected supported against canned SSLv2 server-hello")
	}
}

func TestProbe_TLSServerRejects(t *testing.T) {
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
		t.Error("expected not supported against a TLS server")
	}
}

func TestProbe_RefusedConnection(t *testing.T) {
	// Bind+close to obtain a definitely-refused port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port, _ := strconv.Atoi(ln.Addr().(*net.TCPAddr).String()[len("127.0.0.1:"):])
	ln.Close()
	tgt, err := safehttp.NewTarget("https", "example.test", port, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if Probe(context.Background(), tgt, 500*time.Millisecond) {
		t.Error("refused connection must report not supported")
	}
}
