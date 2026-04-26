// Package dns implements the DNS-hardening family of WebSec101 checks
// (DNSSEC presence, CAA, AAAA/IPv6, wildcard, dangling CNAME, NS
// diversity, TTL hygiene).
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/Jomar/websec101/internal/checks"
)

// DefaultResolver is used when Target.DNSResolverAddr is empty.
// 1.1.1.1 validates DNSSEC and returns the AD flag, which we need.
const DefaultResolver = "1.1.1.1:53"

const (
	cacheKey = "dns.fetch"
	queryTO  = 4 * time.Second
)

// Result aggregates everything the DNS checks consume from one parallel
// fetch sweep.
type Result struct {
	Hostname string

	A     []net.IP
	AAAA  []net.IP
	CNAME []string
	NS    []string
	CAA   []*mdns.CAA
	DS    []*mdns.DS

	// TTLs observed in the answer for the relevant record types. Zero
	// means no answer was received (or the type wasn't queried).
	ATTL    uint32
	AAAATTL uint32

	// AD is the AuthenticatedData flag from the SOA query — only meaningful
	// when DS records exist (i.e. DNSSEC is enabled).
	AD     bool
	SOAErr error

	// Wildcard captures the probe of a random subdomain.
	Wildcard *WildcardProbe

	// Errors records per-rtype lookup errors for diagnostics.
	Errors map[uint16]error
}

// WildcardProbe records the response to a randomised subdomain query.
type WildcardProbe struct {
	QueryName string
	Resolved  bool
	IPs       []net.IP
}

// Fetch performs (or memoises) the DNS sweep for t.
func Fetch(ctx context.Context, t *checks.Target) (*Result, error) {
	v, err := t.CacheValue(cacheKey, func() (any, error) {
		return doFetch(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	r, _ := v.(*Result)
	if r == nil {
		return nil, errors.New("dns: nil cached result")
	}
	return r, nil
}

func resolverAddr(t *checks.Target) string {
	if t.DNSResolverAddr != "" {
		return t.DNSResolverAddr
	}
	return DefaultResolver
}

// query is the single-shot client call. It does one light retry on
// timeout — DNS UDP losses are common but not worth fighting hard.
func query(ctx context.Context, server string, name string, rtype uint16, dnssec bool) (*mdns.Msg, error) {
	c := &mdns.Client{Net: "udp", Timeout: queryTO}
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), rtype)
	m.RecursionDesired = true
	if dnssec {
		m.SetEdns0(4096, true)
	}

	dctx, cancel := context.WithTimeout(ctx, queryTO)
	defer cancel()

	resp, _, err := c.ExchangeContext(dctx, m, server)
	if err != nil {
		// One retry on plain network errors / timeouts.
		dctx2, cancel2 := context.WithTimeout(ctx, queryTO)
		defer cancel2()
		resp, _, err = c.ExchangeContext(dctx2, m, server)
		if err != nil {
			return nil, err
		}
	}
	// Truncated UDP → upgrade to TCP.
	if resp != nil && resp.Truncated {
		c.Net = "tcp"
		dctx3, cancel3 := context.WithTimeout(ctx, queryTO)
		defer cancel3()
		resp, _, err = c.ExchangeContext(dctx3, m, server)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func doFetch(ctx context.Context, t *checks.Target) *Result {
	r := &Result{Hostname: t.Hostname, Errors: map[uint16]error{}}
	server := resolverAddr(t)

	type job struct {
		rtype uint16
		fn    func(*mdns.Msg)
	}
	jobs := []job{
		{mdns.TypeA, func(m *mdns.Msg) {
			for _, rr := range m.Answer {
				if a, ok := rr.(*mdns.A); ok {
					r.A = append(r.A, a.A)
					if r.ATTL == 0 {
						r.ATTL = a.Hdr.Ttl
					}
				}
			}
		}},
		{mdns.TypeAAAA, func(m *mdns.Msg) {
			for _, rr := range m.Answer {
				if a, ok := rr.(*mdns.AAAA); ok {
					r.AAAA = append(r.AAAA, a.AAAA)
					if r.AAAATTL == 0 {
						r.AAAATTL = a.Hdr.Ttl
					}
				}
			}
		}},
		{mdns.TypeCNAME, func(m *mdns.Msg) {
			for _, rr := range m.Answer {
				if c, ok := rr.(*mdns.CNAME); ok {
					r.CNAME = append(r.CNAME, strings.TrimSuffix(c.Target, "."))
				}
			}
		}},
		{mdns.TypeNS, func(m *mdns.Msg) {
			for _, rr := range m.Answer {
				if ns, ok := rr.(*mdns.NS); ok {
					r.NS = append(r.NS, strings.TrimSuffix(ns.Ns, "."))
				}
			}
		}},
		{mdns.TypeCAA, func(m *mdns.Msg) {
			for _, rr := range m.Answer {
				if c, ok := rr.(*mdns.CAA); ok {
					r.CAA = append(r.CAA, c)
				}
			}
		}},
		{mdns.TypeDS, func(m *mdns.Msg) {
			for _, rr := range m.Answer {
				if d, ok := rr.(*mdns.DS); ok {
					r.DS = append(r.DS, d)
				}
			}
		}},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			resp, err := query(ctx, server, t.Hostname, j.rtype, false)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				r.Errors[j.rtype] = err
				return
			}
			if resp == nil {
				return
			}
			j.fn(resp)
		}(j)
	}

	// SOA + DNSSEC OK probe — separate so we can capture the AD flag.
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := query(ctx, server, t.Hostname, mdns.TypeSOA, true)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			r.SOAErr = err
			return
		}
		if resp != nil {
			r.AD = resp.AuthenticatedData
		}
	}()

	// Wildcard probe.
	wg.Add(1)
	go func() {
		defer wg.Done()
		probe := wildcardProbe(ctx, server, t.Hostname)
		mu.Lock()
		defer mu.Unlock()
		r.Wildcard = probe
	}()

	wg.Wait()
	return r
}

func wildcardProbe(ctx context.Context, server, host string) *WildcardProbe {
	// 12 random hex characters keeps the chance of a real-zone collision
	// essentially zero.
	rand := fmt.Sprintf("websec101-%x", time.Now().UnixNano())
	probe := &WildcardProbe{QueryName: rand + "." + host}
	resp, err := query(ctx, server, probe.QueryName, mdns.TypeA, false)
	if err != nil || resp == nil {
		return probe
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return probe
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*mdns.A); ok {
			probe.IPs = append(probe.IPs, a.A)
		}
	}
	probe.Resolved = len(probe.IPs) > 0
	return probe
}
