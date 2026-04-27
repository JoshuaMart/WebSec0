package email

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	mdns "github.com/miekg/dns"

	"github.com/JoshuaMart/websec0/internal/checks"
)

const daneCacheKey = "email.dane"

// TLSARecord is a parsed TLSA resource record (RFC 6698).
type TLSARecord struct {
	Usage     uint8
	Selector  uint8
	MatchType uint8
	DataHex   string // raw hex string from the DNS record
}

// DANEResult holds TLSA records for each MX host.
type DANEResult struct {
	Records map[string][]TLSARecord // MX hostname → TLSA records
	Errors  map[string]error
}

// FetchDANE queries TLSA records at `_25._tcp.{mxHost}` for each MX.
func FetchDANE(ctx context.Context, t *checks.Target) (*DANEResult, error) {
	v, err := t.CacheValue(daneCacheKey, func() (any, error) {
		r, fetchErr := Fetch(ctx, t)
		if fetchErr != nil {
			return nil, fetchErr
		}
		res := &DANEResult{
			Records: map[string][]TLSARecord{},
			Errors:  map[string]error{},
		}
		if !r.HasMX {
			return res, nil
		}
		server := resolverAddr(t)
		for _, mx := range r.MX {
			name := fmt.Sprintf("_25._tcp.%s", mx)
			recs, err := queryTLSA(ctx, server, name)
			if err != nil {
				res.Errors[mx] = err
			} else {
				res.Records[mx] = recs
			}
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*DANEResult), nil
}

// queryTLSA performs a TLSA DNS lookup and returns parsed records.
func queryTLSA(ctx context.Context, server, name string) ([]TLSARecord, error) {
	c := &mdns.Client{Net: "udp", Timeout: dnsTO}
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(name), mdns.TypeTLSA)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	dctx, cancel := context.WithTimeout(ctx, dnsTO)
	defer cancel()
	resp, _, err := c.ExchangeContext(dctx, m, server)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Rcode == mdns.RcodeNameError {
		return nil, nil
	}
	var out []TLSARecord
	for _, rr := range resp.Answer {
		if tlsa, ok := rr.(*mdns.TLSA); ok {
			out = append(out, TLSARecord{
				Usage:     tlsa.Usage,
				Selector:  tlsa.Selector,
				MatchType: tlsa.MatchingType,
				DataHex:   tlsa.Certificate,
			})
		}
	}
	return out, nil
}

// totalTLSARecords returns the total count across all MX hosts.
func totalTLSARecords(d *DANEResult) int {
	n := 0
	for _, recs := range d.Records {
		n += len(recs)
	}
	return n
}

// --- EMAIL-DANE-MISSING ----------------------------------------------

type daneMissingCheck struct{}

func (daneMissingCheck) ID() string                       { return IDDANEMissing }
func (daneMissingCheck) Family() checks.Family            { return checks.FamilyEmail }
func (daneMissingCheck) DefaultSeverity() checks.Severity { return checks.SeverityLow }
func (daneMissingCheck) Title() string                    { return "DANE/TLSA records published for MX hosts" }
func (daneMissingCheck) Description() string {
	return "DANE (RFC 6698 + RFC 7672) allows MX operators to pin TLS certificates via DNSSEC-signed TLSA records, preventing certificate substitution attacks during SMTP delivery."
}
func (daneMissingCheck) RFCRefs() []string { return []string{"RFC 6698", "RFC 7672"} }

func (daneMissingCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDANEMissing, checks.SeverityLow, err), nil
	}
	if g := gateOnMX(r, IDDANEMissing, checks.SeverityLow); g != nil {
		return g, nil
	}
	dane, err := FetchDANE(ctx, t)
	if err != nil {
		return errFinding(IDDANEMissing, checks.SeverityLow, err), nil
	}
	total := totalTLSARecords(dane)
	ev := map[string]any{"tlsa_record_count": total}
	if total == 0 {
		return fail(IDDANEMissing, checks.SeverityLow,
			"no DANE/TLSA records for any MX host",
			"Publish TLSA records at `_25._tcp.<mx-host>` and enable DNSSEC to pin your MX certificates.",
			ev), nil
	}
	return pass(IDDANEMissing, checks.SeverityLow,
		"DANE/TLSA records present", ev), nil
}

// --- EMAIL-DANE-INVALID-PARAMS ---------------------------------------

type daneInvalidParamsCheck struct{}

func (daneInvalidParamsCheck) ID() string                       { return IDDANEInvalidParams }
func (daneInvalidParamsCheck) Family() checks.Family            { return checks.FamilyEmail }
func (daneInvalidParamsCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (daneInvalidParamsCheck) Title() string                    { return "DANE/TLSA records have valid parameters" }
func (daneInvalidParamsCheck) Description() string {
	return "TLSA records must have Usage (0–3), Selector (0–1), and Matching Type (0–2) within valid ranges per RFC 6698 §7.2. Invalid values cause DANE-aware MTAs to reject mail delivery."
}
func (daneInvalidParamsCheck) RFCRefs() []string { return []string{"RFC 6698 §7.2"} }

func (daneInvalidParamsCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDANEInvalidParams, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDDANEInvalidParams, checks.SeverityHigh); g != nil {
		return g, nil
	}
	dane, err := FetchDANE(ctx, t)
	if err != nil {
		return errFinding(IDDANEInvalidParams, checks.SeverityHigh, err), nil
	}
	if totalTLSARecords(dane) == 0 {
		return skipped(IDDANEInvalidParams, checks.SeverityHigh, "no TLSA records"), nil
	}

	var invalids []string
	for mx, recs := range dane.Records {
		for _, rec := range recs {
			if rec.Usage > 3 || rec.Selector > 1 || rec.MatchType > 2 {
				invalids = append(invalids,
					fmt.Sprintf("%s TLSA %d %d %d", mx, rec.Usage, rec.Selector, rec.MatchType))
			}
		}
	}
	if len(invalids) > 0 {
		return fail(IDDANEInvalidParams, checks.SeverityHigh,
			"TLSA records with invalid parameters",
			"Fix Usage/Selector/MatchingType fields to be within valid ranges (0–3 / 0–1 / 0–2).",
			map[string]any{"invalid_records": invalids}), nil
	}
	return pass(IDDANEInvalidParams, checks.SeverityHigh,
		"all TLSA records have valid parameters", nil), nil
}

// --- EMAIL-DANE-MISMATCH ---------------------------------------------

type daneMismatchCheck struct{}

func (daneMismatchCheck) ID() string                       { return IDDANEMismatch }
func (daneMismatchCheck) Family() checks.Family            { return checks.FamilyEmail }
func (daneMismatchCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (daneMismatchCheck) Title() string                    { return "DANE/TLSA records match the MX certificate" }
func (daneMismatchCheck) Description() string {
	return "If TLSA records don't match the certificate presented by the MX server, DANE-aware senders will abort delivery. This can silently drop legitimate mail."
}
func (daneMismatchCheck) RFCRefs() []string { return []string{"RFC 6698", "RFC 7672"} }

func (daneMismatchCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDDANEMismatch, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDDANEMismatch, checks.SeverityHigh); g != nil {
		return g, nil
	}
	dane, err := FetchDANE(ctx, t)
	if err != nil {
		return errFinding(IDDANEMismatch, checks.SeverityHigh, err), nil
	}
	if totalTLSARecords(dane) == 0 {
		return skipped(IDDANEMismatch, checks.SeverityHigh, "no TLSA records"), nil
	}

	// Need the certificate from STARTTLS to compare.
	smtp, err := FetchSMTP(ctx, t)
	if err != nil || !smtp.Connected || smtp.TLSCert == nil {
		return skipped(IDDANEMismatch, checks.SeverityHigh, //nolint:nilerr
			"STARTTLS cert not available (port 25 blocked or TLS failed)"), nil
	}

	mxRecs, ok := dane.Records[smtp.MXHost]
	if !ok || len(mxRecs) == 0 {
		return skipped(IDDANEMismatch, checks.SeverityHigh,
			"no TLSA records for probed MX host"), nil
	}

	for _, rec := range mxRecs {
		if matches, _ := tlsaMatchesCert(rec, smtp.TLSCert); matches {
			return pass(IDDANEMismatch, checks.SeverityHigh,
				"TLSA record matches the MX certificate",
				map[string]any{"mx_host": smtp.MXHost}), nil
		}
	}
	return fail(IDDANEMismatch, checks.SeverityHigh,
		"no TLSA record matches the MX certificate",
		"Update TLSA records to match the current MX TLS certificate. Use `openssl` or `tlsa` tool to compute the record.",
		map[string]any{"mx_host": smtp.MXHost}), nil
}

// tlsaMatchesCert computes whether the TLSA record's certificate association
// data matches cert according to RFC 6698 §1.1.
func tlsaMatchesCert(tlsa TLSARecord, cert *x509.Certificate) (bool, error) {
	var data []byte
	switch tlsa.Selector {
	case 0: // Full certificate DER
		data = cert.Raw
	case 1: // SubjectPublicKeyInfo DER
		data = cert.RawSubjectPublicKeyInfo
	default:
		return false, fmt.Errorf("unknown selector: %d", tlsa.Selector)
	}

	tlsaBytes, err := hex.DecodeString(tlsa.DataHex)
	if err != nil {
		return false, fmt.Errorf("hex decode: %w", err)
	}

	switch tlsa.MatchType {
	case 0: // Exact match
		return bytes.Equal(data, tlsaBytes), nil
	case 1: // SHA-256
		h := sha256.Sum256(data)
		return bytes.Equal(h[:], tlsaBytes), nil
	case 2: // SHA-512
		h := sha512.Sum512(data)
		return bytes.Equal(h[:], tlsaBytes), nil
	default:
		return false, fmt.Errorf("unknown matching type: %d", tlsa.MatchType)
	}
}
