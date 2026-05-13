// Package scan defines the public payload shapes returned by the scanner
// API. These types mirror SPEC §6.1, §6.4–6.6 and are intended for JSON
// marshalling — the field names are normative.
package scan

import (
	"encoding/json"
	"time"
)

// Status is a per-finding outcome label used in header and custom checks.
type Status string

// Status values.
const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusWarn Status = "warn"
	StatusInfo Status = "info"
)

// Severity is the colour-band attached to TLS cipher rows and vulnerability
// findings.
type Severity string

// Severity values.
const (
	SeverityGood Severity = "good"
	SeverityWarn Severity = "warn"
	SeverityBad  Severity = "bad"
	SeverityInfo Severity = "info"
)

// Probe identifies how a TLS protocol's "offered" flag was measured.
type Probe string

// Probe values.
const (
	ProbeStdlib         Probe = "stdlib"
	ProbeRawClientHello Probe = "raw_clienthello"
)

// Result is the top-level scan response (SPEC §6.1).
type Result struct {
	ID         string          `json:"id"`
	Host       string          `json:"host"`
	Port       int             `json:"port"`
	ResolvedIP string          `json:"resolved_ip"`
	ScannedAt  time.Time       `json:"scanned_at"`
	DurationMs int64           `json:"duration_ms"`
	TLS        *TLSReport      `json:"tls,omitempty"`
	Headers    *HeadersReport  `json:"headers,omitempty"`
	Custom     []CustomFinding `json:"custom,omitempty"`
}

// TLSReport mirrors SPEC §6.4, extended with: ChainTrust (overall trust
// outcome), OCSPStapling + OCSPStatus (stapling presence and the parsed
// status), CipherPreference (server vs client) and SessionResumption.
type TLSReport struct {
	Grade             Grade                  `json:"grade"`
	Scores            TLSScores              `json:"scores"`
	Protocols         []ProtocolSupport      `json:"protocols"`
	Ciphers           []Cipher               `json:"ciphers"`
	CipherPreference  CipherPreference       `json:"cipher_preference,omitempty"`
	CertificateChain  []Certificate          `json:"certificate_chain"`
	ChainTrust        ChainTrust             `json:"chain_trust"`
	OCSPStapling      bool                   `json:"ocsp_stapling"`
	OCSPStatus        OCSPStatus             `json:"ocsp_status,omitempty"`
	SessionResumption SessionResumption      `json:"session_resumption,omitempty"`
	Vulnerabilities   []VulnerabilityFinding `json:"vulnerabilities"`
}

// CipherPreference reports whose preference drives the negotiated cipher.
type CipherPreference string

// CipherPreference values.
const (
	CipherPreferenceUnknown CipherPreference = ""
	CipherPreferenceServer  CipherPreference = "server"
	CipherPreferenceClient  CipherPreference = "client"
)

// OCSPStatus is the parsed status of an OCSP-stapled response.
type OCSPStatus string

// OCSPStatus values.
const (
	OCSPStatusUnknown    OCSPStatus = ""
	OCSPStatusGood       OCSPStatus = "good"
	OCSPStatusRevoked    OCSPStatus = "revoked"
	OCSPStatusUnknownRev OCSPStatus = "unknown_to_responder"
	OCSPStatusParseError OCSPStatus = "parse_error"
)

// SessionResumption reports whether a second TLS handshake resumes the
// session ticket / session ID issued by the first.
type SessionResumption string

// SessionResumption values.
const (
	SessionResumptionUnknown      SessionResumption = ""
	SessionResumptionSupported    SessionResumption = "supported"
	SessionResumptionNotSupported SessionResumption = "not_supported"
)

// ChainTrust enumerates the outcome of certificate-chain validation.
type ChainTrust string

// ChainTrust values.
const (
	ChainTrustUnknown          ChainTrust = ""
	ChainTrustTrusted          ChainTrust = "trusted"
	ChainTrustNoChain          ChainTrust = "no_chain"
	ChainTrustSelfSigned       ChainTrust = "self_signed"
	ChainTrustExpired          ChainTrust = "expired"
	ChainTrustHostnameMismatch ChainTrust = "hostname_mismatch"
	ChainTrustUntrusted        ChainTrust = "untrusted"
)

// TLSScores is the four-sub-score + final breakdown.
type TLSScores struct {
	Certificate     int `json:"certificate"`
	ProtocolSupport int `json:"protocol_support"`
	KeyExchange     int `json:"key_exchange"`
	CipherStrength  int `json:"cipher_strength"`
	Final           int `json:"final"`
}

// ProtocolSupport describes whether a single TLS/SSL version is offered.
type ProtocolSupport struct {
	Name    string `json:"name"`
	Offered bool   `json:"offered"`
	Probe   Probe  `json:"probe"`
}

// Cipher describes one negotiated or offered cipher suite.
type Cipher struct {
	Protocol string   `json:"protocol"`
	Name     string   `json:"name"`
	Code     string   `json:"code"`
	Strength int      `json:"strength"`
	AEAD     bool     `json:"aead"`
	PFS      bool     `json:"pfs"`
	Level    Severity `json:"level"`
}

// Certificate is one entry in the certification path (leaf → root).
type Certificate struct {
	Step       int       `json:"step"`
	Kind       string    `json:"kind"`
	CommonName string    `json:"cn"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	KeyAlg     string    `json:"key_alg"`
	SigAlg     string    `json:"sig_alg"`
	Serial     string    `json:"serial"`
	SHA256     string    `json:"sha256"`
	SAN        []string  `json:"san"`
	Revocation string    `json:"revocation"`
}

// VulnerabilityFinding records a presence-based check for a named TLS weakness.
type VulnerabilityFinding struct {
	ID    string   `json:"id"`
	CVE   string   `json:"cve,omitempty"`
	State string   `json:"state"`
	Level Severity `json:"level"`
	Body  string   `json:"body"`
}

// HeadersReport mirrors SPEC §6.5.
type HeadersReport struct {
	Grade      Grade                   `json:"grade"`
	Score      int                     `json:"score"`
	Core       map[string]HeaderResult `json:"core"`
	Additional AdditionalHeaders       `json:"additional"`
	// ProbedHost names the host whose response actually populated this
	// report when the original target redirected to a www-sibling
	// (e.g. cloudflare.com → www.cloudflare.com). Empty when the probe
	// stayed on the original host.
	ProbedHost string `json:"probed_host,omitempty"`
}

// HeaderResult is the evaluation of a single response header.
type HeaderResult struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Status  Status `json:"status"`
}

// AdditionalHeaders aggregates the headers that contribute to bonus/malus
// scoring but are not part of the core six.
type AdditionalHeaders struct {
	Server                    *HeaderResult  `json:"server,omitempty"`
	SetCookie                 []CookieResult `json:"set-cookie,omitempty"`
	AccessControlAllowOrigin  *HeaderResult  `json:"access-control-allow-origin,omitempty"`
	CrossOriginOpenerPolicy   *HeaderResult  `json:"cross-origin-opener-policy,omitempty"`
	CrossOriginEmbedderPolicy *HeaderResult  `json:"cross-origin-embedder-policy,omitempty"`
	CrossOriginResourcePolicy *HeaderResult  `json:"cross-origin-resource-policy,omitempty"`
}

// CookieResult describes the flags found on a single Set-Cookie response.
type CookieResult struct {
	Name     string  `json:"name"`
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"httponly"`
	SameSite *string `json:"samesite"`
	Status   Status  `json:"status"`
}

// CustomFinding mirrors SPEC §6.6. The Details payload is finding-specific
// and is left opaque at this layer.
type CustomFinding struct {
	ID      string          `json:"id"`
	Title   string          `json:"title"`
	Status  Status          `json:"status"`
	Details json.RawMessage `json:"details,omitempty"`
}
