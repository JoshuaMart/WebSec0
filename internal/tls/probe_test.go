package tls

import (
	"context"
	stdtls "crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/JoshuaMart/websec0/catalog"
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
	vulns := DeriveWeaknesses(WeaknessInput{Protocols: protocols, Ciphers: ciphers})

	byID := map[string]scan.VulnerabilityFinding{}
	for _, v := range vulns {
		byID[v.ID] = v
	}
	if byID["vuln.poodle"].State != "Vulnerable" {
		t.Error("vuln.poodle: SSLv3 offered → Vulnerable")
	}
	if byID["vuln.poodle"].Title != "POODLE" {
		t.Errorf("vuln.poodle: expected Title=POODLE, got %q", byID["vuln.poodle"].Title)
	}
	if byID["vuln.beast"].State != "Vulnerable" {
		t.Error("vuln.beast: TLS 1.0 offered → Vulnerable")
	}
	if byID["vuln.sweet32"].State != "Vulnerable" {
		t.Error("vuln.sweet32: 3DES offered → Vulnerable")
	}
	if byID["vuln.rc4"].State != "Vulnerable" {
		t.Error("vuln.rc4: RC4 offered → Vulnerable")
	}
	if byID["vuln.drown"].State != "Not vulnerable" {
		t.Error("vuln.drown: SSLv2 not in protocols → Not vulnerable")
	}
	if _, ok := byID["vuln.robot"]; ok {
		t.Error("vuln.robot should no longer be emitted")
	}
}

func TestIsHeartbleedVulnerable(t *testing.T) {
	cases := map[string]bool{
		"":                                     false,
		"nginx/1.27.1":                         false,
		"Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1f": true,
		"Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips":   true,
		"Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1":         true,
		"Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1a":        true,
		"Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1g":        false, // patched
		"Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1z":        false,
		"Apache/2.4.7 (Ubuntu) OpenSSL/1.0.2k":        false,
		"Apache/2.4.7 (Ubuntu) OpenSSL/3.0.1":         false,
		"openssl/1.0.1F":                              true, // case-insensitive
		"Server-OpenSSL/1.0.1e-fips Mod_security/3.0": true,
	}
	for in, want := range cases {
		if got := isHeartbleedVulnerable(in); got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}

func TestDeriveWeaknesses_HeartbleedFromServerHeader(t *testing.T) {
	vulns := DeriveWeaknesses(WeaknessInput{ServerHeader: "Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1f"})
	h := findVulnByID(vulns, "vuln.heartbleed")
	if h == nil || h.State != "Vulnerable" {
		t.Errorf("Heartbleed: expected Vulnerable for OpenSSL 1.0.1f, got %+v", h)
	}

	vulns = DeriveWeaknesses(WeaknessInput{ServerHeader: "Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1g"})
	h = findVulnByID(vulns, "vuln.heartbleed")
	if h == nil || h.State != "Not vulnerable" {
		t.Errorf("Heartbleed: 1.0.1g is patched, got %+v", h)
	}
}

func TestDeriveWeaknesses_Lucky13(t *testing.T) {
	// TLS 1.0 + CBC cipher on TLS 1.0 → Vulnerable.
	protocols := []scan.ProtocolSupport{{Name: "TLS 1.0", Offered: true}}
	ciphers := []scan.Cipher{{Protocol: "TLS 1.0", Name: "TLS_RSA_WITH_AES_256_CBC_SHA", AEAD: false}}
	vulns := DeriveWeaknesses(WeaknessInput{Protocols: protocols, Ciphers: ciphers})
	l := findVulnByID(vulns, "vuln.lucky13")
	if l == nil || l.State != "Vulnerable" {
		t.Errorf("Lucky13: expected Vulnerable, got %+v", l)
	}

	// TLS 1.2 + CBC → not Lucky13 (mitigations are in TLS 1.2 server impls).
	protocols = []scan.ProtocolSupport{{Name: "TLS 1.2", Offered: true}}
	ciphers = []scan.Cipher{{Protocol: "TLS 1.2", Name: "TLS_RSA_WITH_AES_256_CBC_SHA", AEAD: false}}
	vulns = DeriveWeaknesses(WeaknessInput{Protocols: protocols, Ciphers: ciphers})
	l = findVulnByID(vulns, "vuln.lucky13")
	if l == nil || l.State != "Not vulnerable" {
		t.Errorf("Lucky13: TLS 1.2 + CBC should not trigger, got %+v", l)
	}
}

func TestDeriveWeaknesses_Ticketbleed(t *testing.T) {
	vulns := DeriveWeaknesses(WeaknessInput{ServerHeader: "BIG-IP"})
	tb := findVulnByID(vulns, "vuln.ticketbleed")
	if tb == nil || tb.State != "Potentially vulnerable" || tb.Level != scan.SeverityWarn {
		t.Errorf("Ticketbleed: expected Potentially vulnerable + warn, got %+v", tb)
	}

	vulns = DeriveWeaknesses(WeaknessInput{ServerHeader: "nginx/1.27.1"})
	tb = findVulnByID(vulns, "vuln.ticketbleed")
	if tb == nil || tb.State != "Not vulnerable" {
		t.Errorf("Ticketbleed: nginx server should not trigger, got %+v", tb)
	}
}

// TestDeriveWeaknesses_IDsAlignedWithCatalog asserts that every weakness
// finding emitted at runtime has a matching entry in catalog/checks.json.
// This is the invariant that lets agents and the frontend join
// finding.ID against /api/v1/checks without any string normalisation.
func TestDeriveWeaknesses_IDsAlignedWithCatalog(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	vulns := DeriveWeaknesses(WeaknessInput{})
	for _, v := range vulns {
		if !strings.HasPrefix(v.ID, "vuln.") {
			t.Errorf("finding ID %q must use the vuln.* namespace", v.ID)
		}
		if v.Title == "" {
			t.Errorf("finding %q: Title is empty", v.ID)
		}
		if cat.ByID(v.ID) == nil {
			t.Errorf("finding %q has no matching entry in catalog/checks.json", v.ID)
		}
	}
}

func findVulnByID(vulns []scan.VulnerabilityFinding, id string) *scan.VulnerabilityFinding {
	for i := range vulns {
		if vulns[i].ID == id {
			return &vulns[i]
		}
	}
	return nil
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
