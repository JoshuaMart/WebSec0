// Package email inspects published email-authentication DNS policies. It does
// not send mail or connect to any server named in a policy.
package email

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/JoshuaMart/websec0/internal/safehttp"
	"github.com/JoshuaMart/websec0/internal/scan"
)

const (
	probeTimeout  = 5 * time.Second
	lookupTimeout = 2 * time.Second
	maxTXTRecords = 128
	maxTXTBytes   = 64 << 10
)

// Domain selects only a registrable domain or its exact www alias. PSL private
// suffixes are included so hosted tenants are not attributed to their provider.
func Domain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix, icann := publicsuffix.PublicSuffix(host)
	if !icann && !strings.Contains(suffix, ".") {
		return "" // Unknown/internal suffix: no reliable automatic selection.
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || (host != domain && host != "www."+domain) {
		return ""
	}
	return domain
}

// Probe runs within the scan deadline and its own DNS budget. Nil means the
// host is ineligible, not that email authentication records are absent.
func Probe(ctx context.Context, host string, lookup safehttp.TXTLookupFunc) *scan.EmailReport {
	domain := Domain(host)
	if domain == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if lookup == nil {
		lookup = safehttp.LookupTXT
	}
	q := func(name string) ([]string, error) { return lookupRecords(ctx, name, lookup) }
	out := &scan.EmailReport{Domain: domain, SPF: inspectSPF(domain, q), DMARC: inspectDMARC(domain, q)}
	// Observe both root policies before spending the remaining budget on dependencies.
	if out.SPF.State == scan.DNSRecordObserved {
		out.SPF.Audit = auditSPF(domain, &out.SPF, q)
	}
	out.SPF.Assessment = assessSPF(&out.SPF)
	out.DMARC.Assessment = assessDMARC(&out.DMARC)
	return out
}

type lookupFunc func(string) ([]string, error)

func lookupRecords(ctx context.Context, name string, lookup safehttp.TXTLookupFunc) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records, err := lookup(ctx, name)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTimeout && !dnsErr.IsTemporary {
			return nil, nil
		}
		return nil, err
	}
	if len(records) > maxTXTRecords {
		return nil, errors.New("TXT record limit exceeded")
	}
	size := 0
	for _, record := range records {
		size += len(record)
		if size > maxTXTBytes {
			return nil, errors.New("TXT response size limit exceeded")
		}
	}
	return records, nil
}

func newRecord(id string) scan.DNSRecord {
	return scan.DNSRecord{ID: id, State: scan.DNSRecordAbsent, Records: []string{}, Warnings: []string{}}
}

func unavailable(record *scan.DNSRecord, name string) {
	record.State = scan.DNSRecordUnavailable
	record.Warnings = append(record.Warnings, fmt.Sprintf("DNS lookup for %s failed or exceeded the scan limits; absence could not be determined.", name))
}
