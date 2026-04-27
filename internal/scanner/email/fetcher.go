// Package email implements the email-security family (SPF, DKIM, DMARC,
// MTA-STS, TLS-RPT, BIMI). Every check shares a single parallel DNS
// sweep memoised on Target via CacheValue.
//
// Active SMTP probes (STARTTLS on port 25, DANE/TLSA) and DMARC alignment
// checks are scoped to a follow-up phase.
package email

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/JoshuaMart/websec0/internal/checks"
)

const (
	cacheKey       = "email.fetch"
	dnsTO          = 4 * time.Second
	httpsTO        = 8 * time.Second
	defaultDNSAddr = "1.1.1.1:53"
)

// CommonDKIMSelectors covers the ~20 most-deployed selectors. We probe
// them in parallel; finding any indicates DKIM is set up.
var CommonDKIMSelectors = []string{
	"default", "dkim", "dkim1", "dkim2",
	"google", "k1", "k2", "k3",
	"selector1", "selector2",
	"mandrill", "mailgun", "sendgrid",
	"mxvault", "smtpapi",
	"m1", "mail", "mta", "smtp",
	"scph0118", "scph0918",
	"s1", "s2",
	"protonmail", "pm",
}

// Result is the per-Target snapshot all email checks consume.
type Result struct {
	Hostname string

	MX    []string
	HasMX bool
	MXErr error

	// SPF: TXT records on the apex containing v=spf1 (RFC 7208 §3 mandates
	// at most one).
	SPF    []string
	SPFRaw []string // raw TXT records that started with v=spf1
	SPFErr error

	// DKIM: parallel TXT lookups against `<sel>._domainkey.<apex>`.
	// Only selectors that returned a DKIM record are recorded.
	DKIM     map[string]string // selector → raw record
	DKIMErrs map[string]error

	// DMARC: TXT on `_dmarc.<apex>`.
	DMARC    string
	DMARCErr error

	// MTA-STS TXT and policy file.
	MTASTSTxt    string
	MTASTSPolicy string // body of /.well-known/mta-sts.txt (limited)
	MTASTSErr    error

	// TLS-RPT: TXT on `_smtp._tls.<apex>`.
	TLSRPT    string
	TLSRPTErr error

	// BIMI: TXT on `default._bimi.<apex>`.
	BIMI    string
	BIMIErr error
}

// Fetch runs (or memoises) the email-data sweep.
func Fetch(ctx context.Context, t *checks.Target) (*Result, error) {
	v, err := t.CacheValue(cacheKey, func() (any, error) {
		return doFetch(ctx, t), nil
	})
	if err != nil {
		return nil, err
	}
	r, _ := v.(*Result)
	if r == nil {
		return nil, errors.New("email: nil cached result")
	}
	return r, nil
}

func resolverAddr(t *checks.Target) string {
	if t.DNSResolverAddr != "" {
		return t.DNSResolverAddr
	}
	return defaultDNSAddr
}

// queryTXT performs one TXT lookup, joining each record's strings into a
// single value (RFC 1035 lets TXT records be split into multiple
// 255-byte strings; semantically we treat them as concatenated).
//
// Many real domains publish a chunky TXT record-set (SPF + verification
// tokens for half a dozen vendors). We request a 4096-byte EDNS0 buffer
// and fall back to TCP if the answer is still truncated, otherwise the
// SPF record can disappear behind the UDP MTU.
func queryTXT(ctx context.Context, server, name string) ([]string, error) {
	c := &mdns.Client{Net: "udp", Timeout: dnsTO}
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), mdns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	dctx, cancel := context.WithTimeout(ctx, dnsTO)
	defer cancel()
	resp, _, err := c.ExchangeContext(dctx, m, server)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Truncated {
		c.Net = "tcp"
		dctx2, cancel2 := context.WithTimeout(ctx, dnsTO)
		defer cancel2()
		resp, _, err = c.ExchangeContext(dctx2, m, server)
		if err != nil {
			return nil, err
		}
	}
	if resp == nil || resp.Rcode == mdns.RcodeNameError {
		return nil, nil
	}
	var out []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*mdns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

// queryMX returns the list of MX host targets.
func queryMX(ctx context.Context, server, name string) ([]string, error) {
	c := &mdns.Client{Net: "udp", Timeout: dnsTO}
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), mdns.TypeMX)
	m.RecursionDesired = true

	dctx, cancel := context.WithTimeout(ctx, dnsTO)
	defer cancel()
	resp, _, err := c.ExchangeContext(dctx, m, server)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range resp.Answer {
		if mx, ok := rr.(*mdns.MX); ok {
			out = append(out, strings.TrimSuffix(mx.Mx, "."))
		}
	}
	return out, nil
}

func doFetch(ctx context.Context, t *checks.Target) *Result {
	r := &Result{
		Hostname: t.Hostname,
		DKIM:     map[string]string{},
		DKIMErrs: map[string]error{},
	}
	server := resolverAddr(t)

	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		mxs, err := queryMX(ctx, server, t.Hostname)
		mu.Lock()
		defer mu.Unlock()
		r.MX = mxs
		r.HasMX = len(mxs) > 0
		r.MXErr = err
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, err := queryTXT(ctx, server, t.Hostname)
		mu.Lock()
		defer mu.Unlock()
		r.SPFErr = err
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
				r.SPF = append(r.SPF, txt)
				r.SPFRaw = append(r.SPFRaw, txt)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, err := queryTXT(ctx, server, "_dmarc."+t.Hostname)
		mu.Lock()
		defer mu.Unlock()
		r.DMARCErr = err
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
				r.DMARC = txt
				break
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, err := queryTXT(ctx, server, "_mta-sts."+t.Hostname)
		mu.Lock()
		r.MTASTSErr = err
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=stsv1") {
				r.MTASTSTxt = txt
				break
			}
		}
		mu.Unlock()
		// If MTA-STS TXT is present, fetch the policy file.
		if r.MTASTSTxt != "" {
			body := fetchMTASTSPolicy(ctx, t)
			mu.Lock()
			r.MTASTSPolicy = body
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, err := queryTXT(ctx, server, "_smtp._tls."+t.Hostname)
		mu.Lock()
		defer mu.Unlock()
		r.TLSRPTErr = err
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=tlsrptv1") {
				r.TLSRPT = txt
				break
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, err := queryTXT(ctx, server, "default._bimi."+t.Hostname)
		mu.Lock()
		defer mu.Unlock()
		r.BIMIErr = err
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=bimi1") {
				r.BIMI = txt
				break
			}
		}
	}()

	// Parallel DKIM selector probes.
	for _, sel := range CommonDKIMSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			txts, err := queryTXT(ctx, server, sel+"._domainkey."+t.Hostname)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				r.DKIMErrs[sel] = err
				return
			}
			for _, txt := range txts {
				if strings.Contains(strings.ToLower(txt), "v=dkim1") || strings.Contains(strings.ToLower(txt), "k=rsa") || strings.Contains(strings.ToLower(txt), "p=") {
					r.DKIM[sel] = txt
					break
				}
			}
		}(sel)
	}

	wg.Wait()
	return r
}

func fetchMTASTSPolicy(ctx context.Context, t *checks.Target) string {
	cctx, cancel := context.WithTimeout(ctx, httpsTO)
	defer cancel()

	url := "https://mta-sts." + t.Hostname + "/.well-known/mta-sts.txt"
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", t.UA())
	client := t.Client()
	if client == http.DefaultClient {
		client = &http.Client{Timeout: httpsTO}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	return string(body)
}
