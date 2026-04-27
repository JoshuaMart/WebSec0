package email

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/JoshuaMart/websec0/internal/checks"
)

const (
	starttlsCacheKey = "email.starttls"
	smtpDialTimeout  = 5 * time.Second
	smtpTotalTimeout = 20 * time.Second
)

// SMTPProbeResult holds the outcome of the SMTP/STARTTLS probe against the
// domain's primary MX host on port 25.
type SMTPProbeResult struct {
	MXHost      string            // hostname probed
	Connected   bool              // TCP connection to port 25 succeeded
	STARTTLSAdv bool              // STARTTLS advertised in EHLO capabilities
	TLSVersion  uint16            // negotiated TLS version (0 if not established)
	TLSCert     *x509.Certificate // leaf cert from STARTTLS (nil if none)
	Err         error             // last connection or protocol error
}

// FetchSMTP performs (or memoises) the STARTTLS probe for the target.
// It tries each MX host in turn until one accepts a TCP connection.
// If port 25 is blocked globally, Connected remains false.
func FetchSMTP(ctx context.Context, t *checks.Target) (*SMTPProbeResult, error) {
	v, err := t.CacheValue(starttlsCacheKey, func() (any, error) {
		r, fetchErr := Fetch(ctx, t)
		if fetchErr != nil {
			return &SMTPProbeResult{Err: fetchErr}, nil
		}
		if !r.HasMX || len(r.MX) == 0 {
			return &SMTPProbeResult{}, nil
		}
		for _, mx := range r.MX {
			res := probeSMTP(ctx, mx)
			if res.Connected {
				return res, nil
			}
		}
		// None reachable — return the probe result for the first MX.
		return probeSMTP(ctx, r.MX[0]), nil
	})
	if err != nil {
		return nil, err
	}
	res, _ := v.(*SMTPProbeResult)
	if res == nil {
		return &SMTPProbeResult{}, nil
	}
	return res, nil
}

// probeSMTP connects to mxHost:25, performs the SMTP greeting + EHLO exchange,
// and optionally upgrades to TLS via STARTTLS.
func probeSMTP(ctx context.Context, mxHost string) *SMTPProbeResult {
	res := &SMTPProbeResult{MXHost: mxHost}

	dctx, cancel := context.WithTimeout(ctx, smtpDialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", mxHost+":25")
	if err != nil {
		res.Err = err
		return res
	}
	res.Connected = true
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(smtpTotalTimeout))

	r := bufio.NewReader(conn)

	// Read SMTP greeting (220 ...).
	if _, code, err := readSMTPResponse(r); err != nil || code != "220" {
		res.Err = fmt.Errorf("banner: code=%s err=%w", code, err)
		return res
	}

	// EHLO.
	if _, err := fmt.Fprintf(conn, "EHLO websec0-probe.invalid\r\n"); err != nil {
		res.Err = fmt.Errorf("EHLO write: %w", err)
		return res
	}
	caps, code, err := readSMTPResponse(r)
	if err != nil || code != "250" {
		res.Err = fmt.Errorf("EHLO: code=%s err=%w", code, err)
		return res
	}

	for _, cap := range caps {
		if strings.EqualFold(strings.TrimSpace(cap), "STARTTLS") {
			res.STARTTLSAdv = true
			break
		}
	}
	if !res.STARTTLSAdv {
		return res
	}

	// Upgrade to TLS.
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		res.Err = fmt.Errorf("STARTTLS write: %w", err)
		return res
	}
	_, code, err = readSMTPResponse(r)
	if err != nil || code != "220" {
		res.Err = fmt.Errorf("STARTTLS command: code=%s err=%w", code, err)
		return res
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         mxHost,
		InsecureSkipVerify: true, //#nosec G402 -- deliberate for scanning
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		res.Err = fmt.Errorf("TLS handshake: %w", err)
		return res
	}
	st := tlsConn.ConnectionState()
	res.TLSVersion = st.Version
	if len(st.PeerCertificates) > 0 {
		res.TLSCert = st.PeerCertificates[0]
	}
	return res
}

// readSMTPResponse reads a (possibly multi-line) SMTP response and returns
// the per-line texts (without the 3-digit code prefix), the response code,
// and any read error.
func readSMTPResponse(r *bufio.Reader) (lines []string, code string, err error) {
	for {
		line, readErr := r.ReadString('\n')
		if readErr != nil {
			return nil, code, readErr
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return nil, "", errors.New("short SMTP line")
		}
		if code == "" {
			code = line[:3]
		}
		if len(line) > 4 {
			lines = append(lines, line[4:])
		}
		if len(line) == 3 || line[3] == ' ' {
			return lines, code, nil
		}
	}
}

// --- EMAIL-STARTTLS-FAIL ---------------------------------------------

type startTLSFailCheck struct{}

func (startTLSFailCheck) ID() string                       { return IDSTARTTLSFail }
func (startTLSFailCheck) Family() checks.Family            { return checks.FamilyEmail }
func (startTLSFailCheck) DefaultSeverity() checks.Severity { return checks.SeverityHigh }
func (startTLSFailCheck) Title() string                    { return "MX server advertises STARTTLS" }
func (startTLSFailCheck) Description() string {
	return "STARTTLS (RFC 3207) allows MTAs to negotiate TLS before delivering mail. Without it, all email transit to this domain is in cleartext and interceptable."
}
func (startTLSFailCheck) RFCRefs() []string { return []string{"RFC 3207"} }

func (startTLSFailCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSTARTTLSFail, checks.SeverityHigh, err), nil
	}
	if g := gateOnMX(r, IDSTARTTLSFail, checks.SeverityHigh); g != nil {
		return g, nil
	}
	smtp, err := FetchSMTP(ctx, t)
	if err != nil {
		return errFinding(IDSTARTTLSFail, checks.SeverityHigh, err), nil
	}
	if !smtp.Connected {
		return skipped(IDSTARTTLSFail, checks.SeverityHigh,
			"port 25 unreachable (firewall or ISP blocking)"), nil
	}
	ev := map[string]any{"mx_host": smtp.MXHost}
	if smtp.STARTTLSAdv {
		return pass(IDSTARTTLSFail, checks.SeverityHigh,
			"STARTTLS advertised by MX", ev), nil
	}
	return fail(IDSTARTTLSFail, checks.SeverityHigh,
		"STARTTLS not advertised on port 25",
		"Enable STARTTLS on your MX servers. All major MTAs (Postfix, Exim, Exchange) support it.",
		ev), nil
}

// --- EMAIL-STARTTLS-WEAK-TLS -----------------------------------------

type startTLSWeakTLSCheck struct{}

func (startTLSWeakTLSCheck) ID() string                       { return IDSTARTTLSWeakTLS }
func (startTLSWeakTLSCheck) Family() checks.Family            { return checks.FamilyEmail }
func (startTLSWeakTLSCheck) DefaultSeverity() checks.Severity { return checks.SeverityMedium }
func (startTLSWeakTLSCheck) Title() string                    { return "STARTTLS negotiates TLS 1.2 or higher" }
func (startTLSWeakTLSCheck) Description() string {
	return "TLS 1.0 and 1.1 were deprecated by RFC 8996 (March 2021). SMTP STARTTLS should use TLS 1.2 as the minimum to protect mail transit."
}
func (startTLSWeakTLSCheck) RFCRefs() []string { return []string{"RFC 3207", "RFC 8996"} }

func (startTLSWeakTLSCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	r, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDSTARTTLSWeakTLS, checks.SeverityMedium, err), nil
	}
	if g := gateOnMX(r, IDSTARTTLSWeakTLS, checks.SeverityMedium); g != nil {
		return g, nil
	}
	smtp, err := FetchSMTP(ctx, t)
	if err != nil {
		return errFinding(IDSTARTTLSWeakTLS, checks.SeverityMedium, err), nil
	}
	if !smtp.Connected {
		return skipped(IDSTARTTLSWeakTLS, checks.SeverityMedium, "port 25 unreachable"), nil
	}
	if !smtp.STARTTLSAdv {
		return skipped(IDSTARTTLSWeakTLS, checks.SeverityMedium, "STARTTLS not offered"), nil
	}
	if smtp.TLSVersion == 0 {
		return skipped(IDSTARTTLSWeakTLS, checks.SeverityMedium, "TLS handshake failed"), nil
	}
	ev := map[string]any{
		"mx_host":     smtp.MXHost,
		"tls_version": smtpVersionString(smtp.TLSVersion),
	}
	const tls12 = 0x0303
	if smtp.TLSVersion < tls12 {
		return fail(IDSTARTTLSWeakTLS, checks.SeverityMedium,
			"STARTTLS uses legacy TLS (< 1.2)",
			"Configure the MX server to require TLS 1.2 minimum (`smtpd_tls_protocols` in Postfix, `ssl_ciphers` in Exim).",
			ev), nil
	}
	return pass(IDSTARTTLSWeakTLS, checks.SeverityMedium,
		"STARTTLS uses TLS 1.2 or higher", ev), nil
}

func smtpVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}
