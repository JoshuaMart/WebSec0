package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

// newTLS13ListenerWithBlackhole spins up a TLS 1.3-only listener that
// performs a real handshake for the first goodAccepts connections, then
// silently holds subsequent connections so the client's handshake deadline
// fires (classified as "timeout" by the detector). This reproduces the
// WAF IP-ban pattern: the target accepts the TCP connection but stops
// replying once a legacy ClientHello has been fingerprinted.
func newTLS13ListenerWithBlackhole(t *testing.T, goodAccepts int) (net.Listener, *atomic.Int64) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.test"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS13,
		MaxVersion:   stdtls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var counter atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := int(counter.Add(1))
			if n <= goodAccepts {
				go func(c net.Conn) {
					tc := stdtls.Server(c, tlsCfg)
					_ = tc.Handshake()
					_ = tc.Close()
				}(conn)
				continue
			}
			// Blackhole: hold the TCP conn without responding. Closing it
			// here would surface as EOF and classify as "eof" — which by
			// design does NOT trip the ban detector. Holding silently
			// produces the "timeout" we need to exercise the abort path.
			go func(c net.Conn) {
				time.Sleep(5 * time.Second)
				_ = c.Close()
			}(conn)
		}
	}()
	return ln, &counter
}

// TestProbe_BannedMidScan exercises the full ban-resilient path: the
// listener answers the first three handshakes (extractChain, TLS 1.3
// protocol probe, TLS 1.3 cipher capture) and then blackholes everything
// else. The probe must record TLS 1.3 as offered, mark TLS 1.2/1.1/1.0 as
// ProbeAborted (not "not offered"), and surface ScanStatus partial_blocked.
// The vulnerability list must include vuln.scan_blocked with Partial state.
func TestProbe_BannedMidScan(t *testing.T) {
	if testing.Short() {
		t.Skip("relies on the 3s handshake timeout")
	}
	ln, _ := newTLS13ListenerWithBlackhole(t, 3)
	defer func() { _ = ln.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	tgt, err := safehttp.NewTarget("https", "example.test", port, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}

	report := Probe(context.Background(), tgt)

	if report.ScanStatus != scan.TLSScanStatusPartialBlocked {
		t.Fatalf("expected ScanStatus=partial_blocked, got %q", report.ScanStatus)
	}

	byName := map[string]scan.ProtocolSupport{}
	for _, p := range report.Protocols {
		byName[p.Name] = p
	}
	if got, want := byName["TLS 1.3"].Probe, scan.ProbeStdlib; got != want {
		t.Errorf("TLS 1.3 probe = %q, want %q", got, want)
	}
	if !byName["TLS 1.3"].Offered {
		t.Error("TLS 1.3 should be reported as offered (the listener accepted it)")
	}
	for _, v := range []string{"TLS 1.2", "TLS 1.1", "TLS 1.0"} {
		row, ok := byName[v]
		if !ok {
			t.Errorf("%s missing from protocols list", v)
			continue
		}
		if row.Probe != scan.ProbeAborted {
			t.Errorf("%s probe = %q, want %q", v, row.Probe, scan.ProbeAborted)
		}
		if row.Offered {
			t.Errorf("%s offered=true on an aborted row", v)
		}
	}

	tls13Ciphers := 0
	for _, c := range report.Ciphers {
		if c.Protocol == "TLS 1.3" {
			tls13Ciphers++
		}
	}
	if tls13Ciphers != 1 {
		t.Errorf("expected exactly one TLS 1.3 cipher captured before the ban, got %d", tls13Ciphers)
	}

	// Vulnerabilities are filled by the orchestrator, but we can call the
	// derivation directly to assert vuln.scan_blocked surfaces in Partial.
	vulns := DeriveWeaknesses(WeaknessInput{
		Protocols:  report.Protocols,
		Ciphers:    report.Ciphers,
		ScanStatus: report.ScanStatus,
	})
	var blocked *scan.VulnerabilityFinding
	for i := range vulns {
		if vulns[i].ID == "vuln.scan_blocked" {
			blocked = &vulns[i]
			break
		}
	}
	if blocked == nil {
		t.Fatal("vuln.scan_blocked missing from DeriveWeaknesses output")
	}
	if blocked.State != "Partial" {
		t.Errorf("vuln.scan_blocked state = %q, want Partial", blocked.State)
	}
	if blocked.Level != scan.SeverityInfo {
		t.Errorf("vuln.scan_blocked level = %q, want info", blocked.Level)
	}
}

// TestProbe_HealthyScanStatus asserts the inverse: a healthy probe sets
// ScanStatus to "complete" and emits vuln.scan_blocked with Complete state.
func TestProbe_HealthyScanStatus(t *testing.T) {
	// Reuse the same listener but with enough goodAccepts that nothing is
	// ever blackholed for a TLS 1.3-only server. ~5 covers the worst case
	// (extractChain + TLS 1.3 protocol + TLS 1.3 cipher + 3 alert rejects
	// for TLS 1.2/1.1/1.0).
	ln, _ := newTLS13ListenerWithBlackhole(t, 50)
	defer func() { _ = ln.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port
	tgt, err := safehttp.NewTarget("https", "example.test", port, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}

	report := Probe(context.Background(), tgt)

	if report.ScanStatus != scan.TLSScanStatusComplete {
		t.Errorf("ScanStatus = %q, want complete", report.ScanStatus)
	}
	for _, p := range report.Protocols {
		if p.Probe == scan.ProbeAborted {
			t.Errorf("no row should be aborted on a healthy scan, got %s", p.Name)
		}
	}
	vulns := DeriveWeaknesses(WeaknessInput{
		Protocols:  report.Protocols,
		Ciphers:    report.Ciphers,
		ScanStatus: report.ScanStatus,
	})
	for _, v := range vulns {
		if v.ID == "vuln.scan_blocked" && v.State != "Complete" {
			t.Errorf("vuln.scan_blocked state = %q on healthy scan, want Complete", v.State)
		}
	}
}
