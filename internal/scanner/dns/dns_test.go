package dns_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/JoshuaMart/websec0/internal/checks"
	scannerdns "github.com/JoshuaMart/websec0/internal/scanner/dns"
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

	// Give the goroutine a moment to start.
	time.Sleep(20 * time.Millisecond)
	return m
}

// setAnswer makes the next queries respond with answers built by fn.
func (m *mockServer) setAnswer(fn func(*mdns.Msg) *mdns.Msg) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answer = fn
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

// reply assembles a reply with the given answer RRs and rcode.
func reply(req *mdns.Msg, rcode int, ans ...mdns.RR) *mdns.Msg {
	r := new(mdns.Msg)
	r.SetReply(req)
	r.Rcode = rcode
	r.Answer = append(r.Answer, ans...)
	r.RecursionAvailable = true
	return r
}

func runCheck(t *testing.T, id string, tgt *checks.Target) *checks.Finding {
	t.Helper()
	r := checks.NewRegistry()
	scannerdns.Register(r)
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

func TestRegisterAddsAllDNSChecks(t *testing.T) {
	t.Parallel()
	r := checks.NewRegistry()
	scannerdns.Register(r)
	for _, id := range []string{
		scannerdns.IDDNSSECMissing, scannerdns.IDDNSSECWeakAlgo, scannerdns.IDDNSSECBroken,
		scannerdns.IDCAAMissing, scannerdns.IDCAANoIODEF,
		scannerdns.IDAAAAMissing, scannerdns.IDWildcardDetect,
		scannerdns.IDDanglingCNAME, scannerdns.IDNSDiversityLow, scannerdns.IDTTLAberrant,
	} {
		if _, ok := r.Get(id); !ok {
			t.Errorf("missing %s", id)
		}
	}
}

func TestNoDSMeansDNSSECMissing(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg { return reply(req, mdns.RcodeSuccess) })
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDDNSSECMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("DNSSEC-MISSING = %s, want fail", g.Status)
	}
}

func TestDSPresentMeansDNSSECPresent(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeDS {
			return reply(req, mdns.RcodeSuccess)
		}
		ds := &mdns.DS{
			Hdr:        mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeDS, Class: mdns.ClassINET, Ttl: 3600},
			KeyTag:     12345,
			Algorithm:  13, // ECDSA-P256
			DigestType: 2,  // SHA-256
			Digest:     "abcd",
		}
		return reply(req, mdns.RcodeSuccess, ds)
	})
	tgt := newTarget(t, "example.com", srv)
	g := runCheck(t, scannerdns.IDDNSSECMissing, tgt)
	if g.Status != checks.StatusPass {
		t.Errorf("DNSSEC-MISSING = %s, want pass", g.Status)
	}
	// Pass evidence must surface the DS records as structured rows with
	// human algorithm labels — not just a count.
	rows, _ := g.Evidence["ds_records"].([]map[string]any)
	if len(rows) != 1 {
		t.Fatalf("ds_records = %v, want 1 row", rows)
	}
	if rows[0]["algorithm_name"] != "ECDSA-P256" {
		t.Errorf("algorithm_name = %v, want ECDSA-P256", rows[0]["algorithm_name"])
	}
	if rows[0]["key_tag"] != uint16(12345) {
		t.Errorf("key_tag = %v, want 12345", rows[0]["key_tag"])
	}
	if g := runCheck(t, scannerdns.IDDNSSECWeakAlgo, tgt); g.Status != checks.StatusPass {
		t.Errorf("DNSSEC-WEAK-ALGO with alg 13 = %s, want pass", g.Status)
	}
}

func TestWeakDNSSECAlgoFails(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeDS {
			return reply(req, mdns.RcodeSuccess)
		}
		ds := &mdns.DS{
			Hdr:        mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeDS, Class: mdns.ClassINET, Ttl: 3600},
			Algorithm:  5, // RSASHA1 (deprecated)
			DigestType: 2,
		}
		return reply(req, mdns.RcodeSuccess, ds)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDDNSSECWeakAlgo, tgt); g.Status != checks.StatusFail {
		t.Errorf("WEAK-ALGO = %s, want fail", g.Status)
	}
}

func TestCAAPresentAndIODEF(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeCAA {
			return reply(req, mdns.RcodeSuccess)
		}
		caa := []mdns.RR{
			&mdns.CAA{
				Hdr:  mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeCAA, Class: mdns.ClassINET, Ttl: 3600},
				Flag: 0, Tag: "issue", Value: "letsencrypt.org",
			},
			&mdns.CAA{
				Hdr:  mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeCAA, Class: mdns.ClassINET, Ttl: 3600},
				Flag: 0, Tag: "iodef", Value: "mailto:abuse@example.com",
			},
		}
		return reply(req, mdns.RcodeSuccess, caa...)
	})
	tgt := newTarget(t, "example.com", srv)
	g := runCheck(t, scannerdns.IDCAAMissing, tgt)
	if g.Status != checks.StatusPass {
		t.Errorf("CAA-MISSING = %s, want pass", g.Status)
	}
	recs, _ := g.Evidence["records"].([]map[string]any)
	if len(recs) != 2 {
		t.Fatalf("records = %v, want 2 rows", recs)
	}
	gi := runCheck(t, scannerdns.IDCAANoIODEF, tgt)
	if gi.Status != checks.StatusPass {
		t.Errorf("CAA-NO-IODEF = %s, want pass", gi.Status)
	}
	if gi.Evidence["iodef"] != "mailto:abuse@example.com" {
		t.Errorf("iodef = %v, want mailto:abuse@example.com", gi.Evidence["iodef"])
	}
}

func TestCAAMissingFails(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg { return reply(req, mdns.RcodeSuccess) })
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDCAAMissing, tgt); g.Status != checks.StatusFail {
		t.Errorf("CAA-MISSING = %s, want fail", g.Status)
	}
}

func TestAAAAPresentPasses(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeAAAA {
			return reply(req, mdns.RcodeSuccess)
		}
		aaaa := &mdns.AAAA{
			Hdr:  mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::1"),
		}
		return reply(req, mdns.RcodeSuccess, aaaa)
	})
	tgt := newTarget(t, "example.com", srv)
	g := runCheck(t, scannerdns.IDAAAAMissing, tgt)
	if g.Status != checks.StatusPass {
		t.Errorf("AAAA-MISSING = %s, want pass", g.Status)
	}
	addrs, _ := g.Evidence["addresses"].([]string)
	if len(addrs) != 1 || addrs[0] != "2001:db8::1" {
		t.Errorf("addresses = %v, want [2001:db8::1]", addrs)
	}
}

func TestNSDiversity(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeNS {
			return reply(req, mdns.RcodeSuccess)
		}
		ns := []mdns.RR{
			&mdns.NS{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 3600}, Ns: "ns1.example.com."},
			&mdns.NS{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 3600}, Ns: "ns2.example.com."},
		}
		return reply(req, mdns.RcodeSuccess, ns...)
	})
	tgt := newTarget(t, "example.com", srv)
	g := runCheck(t, scannerdns.IDNSDiversityLow, tgt)
	if g.Status != checks.StatusPass {
		t.Errorf("NS-DIVERSITY = %s, want pass", g.Status)
	}
	if d, _ := g.Evidence["distinct"].(int); d != 2 {
		t.Errorf("distinct = %v, want 2", g.Evidence["distinct"])
	}
}

func TestNSDiversityFailsWithSingleNS(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeNS {
			return reply(req, mdns.RcodeSuccess)
		}
		ns := &mdns.NS{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		}
		return reply(req, mdns.RcodeSuccess, ns)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDNSDiversityLow, tgt); g.Status != checks.StatusFail {
		t.Errorf("NS-DIVERSITY single = %s, want fail", g.Status)
	}
}

func TestWildcardDetected(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	// All A queries succeed → wildcard probe will resolve.
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeA {
			return reply(req, mdns.RcodeSuccess)
		}
		a := &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   net.ParseIP("203.0.113.10"),
		}
		return reply(req, mdns.RcodeSuccess, a)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDWildcardDetect, tgt); g.Status != checks.StatusWarn {
		t.Errorf("WILDCARD = %s, want warn", g.Status)
	}
}

func TestNoWildcardPasses(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	// A queries return NXDOMAIN → wildcard probe NX → pass.
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		return reply(req, mdns.RcodeNameError)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDWildcardDetect, tgt); g.Status != checks.StatusPass {
		t.Errorf("WILDCARD no-wildcard = %s, want pass", g.Status)
	}
}

func TestDanglingCNAMEDetected(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		switch req.Question[0].Qtype {
		case mdns.TypeCNAME:
			c := &mdns.CNAME{
				Hdr:    mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300},
				Target: "abandoned-bucket.s3.amazonaws.com.",
			}
			return reply(req, mdns.RcodeSuccess, c)
		case mdns.TypeA:
			// CNAME target resolution → NXDOMAIN.
			return reply(req, mdns.RcodeNameError)
		default:
			return reply(req, mdns.RcodeSuccess)
		}
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDDanglingCNAME, tgt); g.Status != checks.StatusFail {
		t.Errorf("DANGLING-CNAME = %s, want fail", g.Status)
	}
}

func TestTTLAberrantTooLow(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeA {
			return reply(req, mdns.RcodeSuccess)
		}
		a := &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 5},
			A:   net.ParseIP("203.0.113.10"),
		}
		return reply(req, mdns.RcodeSuccess, a)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDTTLAberrant, tgt); g.Status != checks.StatusWarn {
		t.Errorf("TTL-ABERRANT (5s) = %s, want warn", g.Status)
	}
}

func TestTTLAberrantTooHigh(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		if req.Question[0].Qtype != mdns.TypeA {
			return reply(req, mdns.RcodeSuccess)
		}
		a := &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 86400 * 30},
			A:   net.ParseIP("203.0.113.10"),
		}
		return reply(req, mdns.RcodeSuccess, a)
	})
	tgt := newTarget(t, "example.com", srv)
	if g := runCheck(t, scannerdns.IDTTLAberrant, tgt); g.Status != checks.StatusWarn {
		t.Errorf("TTL-ABERRANT (30d) = %s, want warn", g.Status)
	}
}

func TestFetchIsCachedAcrossChecks(t *testing.T) {
	t.Parallel()
	srv := newMockServer(t)
	var hits int
	var mu sync.Mutex
	srv.setAnswer(func(req *mdns.Msg) *mdns.Msg {
		mu.Lock()
		hits++
		mu.Unlock()
		return reply(req, mdns.RcodeSuccess)
	})
	tgt := newTarget(t, "example.com", srv)
	r := checks.NewRegistry()
	scannerdns.Register(r)
	for _, c := range r.All() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = c.Run(ctx, tgt)
		cancel()
	}
	mu.Lock()
	defer mu.Unlock()
	// We do 6 typed queries + SOA + wildcard probe + a possible CNAME-target
	// resolution. That's 8-9 hits per Fetch, all from one cached Fetch().
	if hits > 9 {
		t.Errorf("server hit %d times, want ≤ 9 (cache appears broken)", hits)
	}
	fmt.Printf("hits=%d\n", hits)
}
