package tls

import (
	"context"
	stdtls "crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

func makeTargetForServer(t *testing.T, srv *httptest.Server) *safehttp.Target {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	tgt, err := safehttp.NewTarget("https", "example.test", port, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return tgt
}

func TestProbe_TLS12Only(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &stdtls.Config{
		MinVersion: stdtls.VersionTLS12,
		MaxVersion: stdtls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	tgt := makeTargetForServer(t, srv)
	report := Probe(context.Background(), tgt)

	offered := map[string]bool{}
	for _, p := range report.Protocols {
		offered[p.Name] = p.Offered
	}
	if !offered["TLS 1.2"] {
		t.Error("TLS 1.2 should be offered")
	}
	if offered["TLS 1.3"] {
		t.Error("TLS 1.3 should not be offered when server is locked to 1.2")
	}
	if offered["TLS 1.0"] || offered["TLS 1.1"] {
		t.Error("TLS 1.0/1.1 should not be offered")
	}
	if len(report.Ciphers) == 0 {
		t.Error("expected at least one cipher enumerated for TLS 1.2")
	}
	for _, c := range report.Ciphers {
		if c.Protocol != "TLS 1.2" {
			t.Errorf("cipher %q reported as protocol %q, expected TLS 1.2", c.Name, c.Protocol)
		}
	}
}

func TestProbe_TLS13_NegotiatedCipherCaptured(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &stdtls.Config{
		MinVersion: stdtls.VersionTLS13,
		MaxVersion: stdtls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()

	tgt := makeTargetForServer(t, srv)
	report := Probe(context.Background(), tgt)

	var tls13Ciphers []scan.Cipher
	for _, c := range report.Ciphers {
		if c.Protocol == "TLS 1.3" {
			tls13Ciphers = append(tls13Ciphers, c)
		}
	}
	if len(tls13Ciphers) != 1 {
		t.Fatalf("expected exactly one TLS 1.3 cipher captured, got %d", len(tls13Ciphers))
	}
	if !tls13Ciphers[0].AEAD || !tls13Ciphers[0].PFS {
		t.Errorf("TLS 1.3 cipher should be AEAD + PFS, got %+v", tls13Ciphers[0])
	}
}

func TestProbe_ChainNotTrustedForHttptest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	tgt := makeTargetForServer(t, srv)
	report := Probe(context.Background(), tgt)

	if report.ChainTrust == scan.ChainTrustTrusted {
		t.Errorf("httptest cert must not validate against system roots, got %s", report.ChainTrust)
	}
	if len(report.CertificateChain) == 0 {
		t.Error("expected at least one certificate in the chain")
	}
	leaf := report.CertificateChain[0]
	if leaf.Kind != "Leaf" {
		t.Errorf("first cert should be Leaf, got %s", leaf.Kind)
	}
	if leaf.SHA256 == "" {
		t.Error("leaf SHA256 fingerprint must be populated")
	}
}

func TestDeriveWeaknesses_FlagsObservedBadness(t *testing.T) {
	protocols := []scan.ProtocolSupport{
		{Name: "TLS 1.2", Offered: true},
		{Name: "TLS 1.0", Offered: true},
		{Name: "SSL 3.0", Offered: true},
	}
	ciphers := []scan.Cipher{
		{Protocol: "TLS 1.0", Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{Protocol: "TLS 1.0", Name: "TLS_RSA_WITH_RC4_128_SHA"},
	}
	vulns := deriveWeaknesses(protocols, ciphers)

	byID := map[string]scan.VulnerabilityFinding{}
	for _, v := range vulns {
		byID[v.ID] = v
	}
	if byID["POODLE"].State != "Vulnerable" {
		t.Error("POODLE: SSLv3 offered → Vulnerable")
	}
	if byID["BEAST"].State != "Vulnerable" {
		t.Error("BEAST: TLS 1.0 offered → Vulnerable")
	}
	if byID["Sweet32"].State != "Vulnerable" {
		t.Error("Sweet32: 3DES offered → Vulnerable")
	}
	if byID["RC4 weakness"].State != "Vulnerable" {
		t.Error("RC4 weakness: RC4 offered → Vulnerable")
	}
	if byID["DROWN"].State != "Not vulnerable" {
		t.Error("DROWN: SSLv2 not in protocols → Not vulnerable")
	}
	if byID["Heartbleed"].Level != scan.SeverityInfo {
		t.Error("Heartbleed: should be info-level (not assessed in passive mode)")
	}
}

func TestCipherStrength(t *testing.T) {
	cases := map[string]int{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 256,
		"TLS_CHACHA20_POLY1305_SHA256":          256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 128,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":         168,
		"TLS_RSA_WITH_RC4_128_SHA":              128,
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA":      256,
	}
	for name, want := range cases {
		if got := cipherStrength(name); got != want {
			t.Errorf("%s: got %d, want %d", name, got, want)
		}
	}
}

func TestIsAEAD_And_HasPFS(t *testing.T) {
	if !isAEAD("TLS_AES_256_GCM_SHA384") || !isAEAD("TLS_CHACHA20_POLY1305_SHA256") {
		t.Error("AEAD detection broken for GCM/CHACHA20")
	}
	if isAEAD("TLS_RSA_WITH_AES_256_CBC_SHA") {
		t.Error("CBC should not be AEAD")
	}
	if !hasPFS("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS 1.2") {
		t.Error("ECDHE should have PFS")
	}
	if hasPFS("TLS_RSA_WITH_AES_256_CBC_SHA", "TLS 1.2") {
		t.Error("RSA-only should not have PFS")
	}
	if !hasPFS("TLS_AES_128_GCM_SHA256", "TLS 1.3") {
		t.Error("TLS 1.3 ciphers are always PFS")
	}
}

func TestFormatFingerprint(t *testing.T) {
	got := formatFingerprint([]byte{0xde, 0xad, 0xbe, 0xef})
	want := "DE:AD:BE:EF"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
