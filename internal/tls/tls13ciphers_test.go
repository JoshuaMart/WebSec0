package tls

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestOfferTLS13Suite_AcceptedByStdlibServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &stdtls.Config{MinVersion: stdtls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	tgt := makeTargetForServer(t, srv)

	for _, s := range tls13Suites() {
		ok, err := offerTLS13Suite(context.Background(), tgt, s.ID)
		if err != nil || !ok {
			t.Errorf("%s: accepted=%v err=%v, want accepted", s.Name, ok, err)
		}
	}
}

func TestOfferTLS13Suite_TLS12OnlyServerRejects(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &stdtls.Config{MaxVersion: stdtls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	tgt := makeTargetForServer(t, srv)

	ok, err := offerTLS13Suite(context.Background(), tgt, stdtls.TLS_AES_128_GCM_SHA256)
	if ok {
		t.Fatal("a TLS 1.2-only server must not accept a TLS 1.3 suite")
	}
	if err == nil || classifyErr(err) != "tls_alert" {
		t.Errorf("want a tls_alert error so the ban detector stays idle, got %v (%s)", err, classifyErr(err))
	}
}

func TestBuildTLS13ClientHello_ParsesWithStdlibShape(t *testing.T) {
	rec, err := buildTLS13ClientHello("example.test", stdtls.TLS_CHACHA20_POLY1305_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if rec[0] != recordTypeHandshake || int(rec[3])<<8|int(rec[4]) != len(rec)-5 {
		t.Fatalf("bad record header % x", rec[:5])
	}
	if !bytes.Contains(rec, []byte("example.test")) {
		t.Error("SNI missing")
	}
	noSNI, err := buildTLS13ClientHello(sniHost("192.0.2.1"), stdtls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(noSNI, []byte("192.0.2.1")) {
		t.Error("an IP literal must not be sent as SNI")
	}
}

func serverHello(suite, version uint16) []byte {
	var b cryptobyte.Builder
	b.AddUint8(handshakeTypeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(stdtls.VersionTLS12)
		b.AddBytes(make([]byte, 32))
		b.AddUint8LengthPrefixed(func(*cryptobyte.Builder) {})
		b.AddUint16(suite)
		b.AddUint8(0)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if version != 0 {
				b.AddUint16(extSupportedVersions)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(version) })
			}
		})
	})
	return b.BytesOrPanic()
}

func record(typ byte, payload []byte) []byte {
	return append([]byte{typ, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func TestReadServerHelloSuite(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		want    uint16
		wantErr error
	}{
		{"TLS 1.3 ServerHello", record(recordTypeHandshake, serverHello(0x1302, stdtls.VersionTLS13)), 0x1302, nil},
		{"alert", record(recordTypeAlert, []byte{2, 40}), 0, errSuiteRejected},
		{"TLS 1.2 ServerHello", record(recordTypeHandshake, serverHello(0xc02f, 0)), 0, errors.New("")},
		{"truncated", record(recordTypeHandshake, serverHello(0x1301, stdtls.VersionTLS13))[:20], 0, errors.New("")},
		{"not a handshake", record(0x17, []byte{1, 2, 3}), 0, errors.New("")},
	}
	for _, c := range cases {
		got, err := readServerHelloSuite(bytes.NewReader(c.in))
		switch {
		case c.wantErr == nil && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantErr != nil && err == nil:
			t.Errorf("%s: want an error, got suite 0x%04X", c.name, got)
		case errors.Is(c.wantErr, errSuiteRejected) && !errors.Is(err, errSuiteRejected):
			t.Errorf("%s: want errSuiteRejected, got %v", c.name, err)
		case c.wantErr == nil && got != c.want:
			t.Errorf("%s: got 0x%04X, want 0x%04X", c.name, got, c.want)
		}
	}
}
