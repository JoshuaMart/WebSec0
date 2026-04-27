package email_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/JoshuaMart/websec0/internal/checks"
	"github.com/JoshuaMart/websec0/internal/scanner/email"
)

// mockServer is a tiny in-process DNS server. The handler is replaced
// per-test to control what gets returned for each (qname, qtype).
type mockServer struct {
	addr   string
	srv    *mdns.Server
	mu     sync.Mutex
	answer func(*mdns.Msg) *mdns.Msg
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	m := &mockServer{addr: pc.LocalAddr().String()}
	srv := &mdns.Server{
		Net:        "udp",
		PacketConn: pc,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
			m.mu.Lock()
			fn := m.answer
			m.mu.Unlock()
			resp := new(mdns.Msg)
			if fn != nil {
				resp = fn(r)
			} else {
				resp.SetReply(r)
			}
			_ = w.WriteMsg(resp)
		}),
	}
	m.srv = srv
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	time.Sleep(20 * time.Millisecond)
	return m
}

func (m *mockServer) setAnswer(fn func(*mdns.Msg) *mdns.Msg) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answer = fn
}

func reply(req *mdns.Msg, ans ...mdns.RR) *mdns.Msg {
	r := new(mdns.Msg)
	r.SetReply(req)
	r.Rcode = mdns.RcodeSuccess
	r.Answer = append(r.Answer, ans...)
	return r
}

// txtRR builds a TXT record with one or more strings.
func txtRR(name string, txt ...string) mdns.RR {
	return &mdns.TXT{
		Hdr: mdns.RR_Header{Name: mdns.Fqdn(name), Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300},
		Txt: txt,
	}
}

func mxRR(name, target string) mdns.RR {
	return &mdns.MX{
		Hdr:        mdns.RR_Header{Name: mdns.Fqdn(name), Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 300},
		Preference: 10, Mx: mdns.Fqdn(target),
	}
}

func newTarget(t *testing.T, hostname string, srv *mockServer) *checks.Target {
	t.Helper()
	tgt, err := checks.NewTarget(hostname, nil)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	tgt.DNSResolverAddr = srv.addr
	return tgt
}

func runCheck(t *testing.T, id string, tgt *checks.Target) *checks.Finding {
	t.Helper()
	r := checks.NewRegistry()
	email.Register(r)
	c, ok := r.Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f, err := c.Run(ctx, tgt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return f
}

func TestRegisterAddsAllEmailChecks(t *testing.T) {
	t.Parallel()
	r := checks.NewRegistry()
	email.Register(r)
	want := []string{
		// SPF
		email.IDSPFMissing, email.IDSPFMultiple, email.IDSPFInvalidSyntax,
		email.IDSPFNoAll, email.IDSPFPassAll, email.IDSPFSoftfailAll,
		email.IDSPFPTRMechanism, email.IDSPFTooManyLookups,
		// DKIM
		email.IDDKIMNoneFound, email.IDDKIMWeakKey, email.IDDKIMSHA1, email.IDDKIMTestMode,
		// DMARC
		email.IDDMARCMissing, email.IDDMARCInvalidSyntax, email.IDDMARCPolicyNone,
		email.IDDMARCPolicyWeak, email.IDDMARCNoRUA,
		email.IDDMARCMisalignedSPF, email.IDDMARCMisalignedDKIM,
		// MTA-STS
		email.IDMTASTSMissing, email.IDMTASTSModeTesting, email.IDMTASTSMaxAgeLow,
		email.IDMTASTSMXMismatch,
		// TLS-RPT + BIMI
		email.IDTLSRPTMissing, email.IDBIMIMissing, email.IDBIMIInvalidSVG,
		// STARTTLS
		email.IDSTARTTLSFail, email.IDSTARTTLSWeakTLS,
		// DANE
		email.IDDANEMissing, email.IDDANEInvalidParams, email.IDDANEMismatch,
	}
	for _, id := range want {
		if _, ok := r.Get(id); !ok {
			t.Errorf("missing %s", id)
		}
	}
	if r.Len() != len(want) {
		t.Errorf("Len = %d, want %d", r.Len(), len(want))
	}
}

func TestNoMXSkipsAllChecks(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg { return reply(req) })
	tgt := newTarget(t, "example.com", srv)
	for _, id := range []string{email.IDSPFMissing, email.IDDMARCMissing, email.IDMTASTSMissing} {
		if g := runCheck(t, id, tgt); g.Status != checks.StatusSkipped {
			t.Errorf("%s = %s, want skipped (no MX)", id, g.Status)
		}
	}
}

// strongFixture returns a server that publishes a very strong email
// configuration: SPF strict, DMARC reject, DKIM with default selector,
// MTA-STS enforced 30 days, TLS-RPT, BIMI.
func strongFixture(t *testing.T) (*mockServer, *checks.Target) {
	t.Helper()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		switch q.Qtype {
		case mdns.TypeMX:
			if name == "example.com" {
				return reply(req, mxRR(name, "mail.example.com"))
			}
		case mdns.TypeTXT:
			switch name {
			case "example.com":
				return reply(req, txtRR(name, "v=spf1 include:_spf.example.com -all"))
			case "_dmarc.example.com":
				return reply(req, txtRR(name, "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"))
			case "default._domainkey.example.com":
				// Realistic DKIM record (key bytes are gibberish but base64 valid).
				return reply(req, txtRR(name, "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxxxxxxx"))
			case "_mta-sts.example.com":
				return reply(req, txtRR(name, "v=STSv1; id=20240101"))
			case "_smtp._tls.example.com":
				return reply(req, txtRR(name, "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"))
			case "default._bimi.example.com":
				return reply(req, txtRR(name, "v=BIMI1; l=https://example.com/logo.svg"))
			}
		}
		return reply(req)
	})
	return srv, newTarget(t, "example.com", srv)
}

func TestSPFEnforced(t *testing.T) {
	t.Parallel()
	_, tgt := strongFixture(t)
	if g := runCheck(t, email.IDSPFMissing, tgt); g.Status != checks.StatusPass {
		t.Errorf("SPF-MISSING = %s, want pass", g.Status)
	}
	if g := runCheck(t, email.IDSPFNoAll, tgt); g.Status != checks.StatusPass {
		t.Errorf("SPF-NO-ALL = %s, want pass", g.Status)
	}
	if g := runCheck(t, email.IDSPFPassAll, tgt); g.Status != checks.StatusPass {
		t.Errorf("SPF-PASS-ALL = %s, want pass", g.Status)
	}
}

func TestSPFPassAllDetected(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		switch q.Qtype {
		case mdns.TypeMX:
			return reply(req, mxRR(name, "mail.example.com"))
		case mdns.TypeTXT:
			if name == "example.com" {
				return reply(req, txtRR(name, "v=spf1 +all"))
			}
		}
		return reply(req)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, email.IDSPFPassAll, tgt); g.Status != checks.StatusFail {
		t.Errorf("SPF-PASS-ALL = %s, want fail", g.Status)
	}
}

func TestSPFPTRDetected(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		switch q.Qtype {
		case mdns.TypeMX:
			return reply(req, mxRR(name, "mail.example.com"))
		case mdns.TypeTXT:
			if name == "example.com" {
				return reply(req, txtRR(name, "v=spf1 ptr -all"))
			}
		}
		return reply(req)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, email.IDSPFPTRMechanism, tgt); g.Status != checks.StatusFail {
		t.Errorf("SPF-PTR = %s, want fail", g.Status)
	}
}

func TestSPFMultipleDetected(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		switch q.Qtype {
		case mdns.TypeMX:
			return reply(req, mxRR(name, "mail.example.com"))
		case mdns.TypeTXT:
			if name == "example.com" {
				return reply(req,
					txtRR(name, "v=spf1 -all"),
					txtRR(name, "v=spf1 ip4:1.2.3.4 -all"),
				)
			}
		}
		return reply(req)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, email.IDSPFMultiple, tgt); g.Status != checks.StatusFail {
		t.Errorf("SPF-MULTIPLE = %s, want fail", g.Status)
	}
}

func TestDMARCPolicyNoneFails(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		q := req.Question[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		switch q.Qtype {
		case mdns.TypeMX:
			return reply(req, mxRR(name, "mail.example.com"))
		case mdns.TypeTXT:
			if name == "_dmarc.example.com" {
				return reply(req, txtRR(name, "v=DMARC1; p=none"))
			}
		}
		return reply(req)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, email.IDDMARCPolicyNone, tgt); g.Status != checks.StatusFail {
		t.Errorf("DMARC-POLICY-NONE = %s, want fail", g.Status)
	}
	if g := runCheck(t, email.IDDMARCNoRUA, tgt); g.Status != checks.StatusFail {
		t.Errorf("DMARC-NO-RUA = %s, want fail", g.Status)
	}
}

func TestDMARCRejectPasses(t *testing.T) {
	t.Parallel()
	_, tgt := strongFixture(t)
	if g := runCheck(t, email.IDDMARCMissing, tgt); g.Status != checks.StatusPass {
		t.Errorf("DMARC-MISSING = %s, want pass", g.Status)
	}
	if g := runCheck(t, email.IDDMARCPolicyNone, tgt); g.Status != checks.StatusPass {
		t.Errorf("DMARC-POLICY-NONE = %s, want pass", g.Status)
	}
	if g := runCheck(t, email.IDDMARCPolicyWeak, tgt); g.Status != checks.StatusPass {
		t.Errorf("DMARC-POLICY-WEAK = %s, want pass", g.Status)
	}
}

func TestDKIMFoundOnDefaultSelector(t *testing.T) {
	t.Parallel()
	_, tgt := strongFixture(t)
	if g := runCheck(t, email.IDDKIMNoneFound, tgt); g.Status != checks.StatusPass {
		t.Errorf("DKIM-NONE-FOUND = %s, want pass", g.Status)
	}
}

func TestDKIMNoneOnUnknownSelectors(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype == mdns.TypeMX {
			return reply(req, mxRR("example.com", "mail.example.com"))
		}
		return reply(req)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, email.IDDKIMNoneFound, tgt); g.Status != checks.StatusFail {
		t.Errorf("DKIM-NONE-FOUND = %s, want fail", g.Status)
	}
}

func TestTLSRPTMissingFails(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype == mdns.TypeMX {
			return reply(req, mxRR("example.com", "mail.example.com"))
		}
		return reply(req)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, email.IDTLSRPTMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("TLSRPT-MISSING = %s, want fail", g.Status)
	}
}

func TestBIMIMissingFails(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype == mdns.TypeMX {
			return reply(req, mxRR("example.com", "mail.example.com"))
		}
		return reply(req)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, email.IDBIMIMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("BIMI-MISSING = %s, want fail", g.Status)
	}
}
