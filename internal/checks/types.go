// Package checks defines the Check interface, the result types, and the
// shared registry/catalog used by both the scanner orchestrator and the
// HTTP API.
//
// Concrete check implementations live in subpackages of internal/scanner
// (e.g. internal/scanner/wellknown, internal/scanner/tls, ...). They
// satisfy the Check interface defined here and self-register at init.
package checks

// Severity grades the impact of a finding. Values match the OpenAPI
// Severity enum; conversion between checks.Severity and client.Severity
// is a no-op string cast.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// FindingStatus is the per-check outcome.
type FindingStatus string

const (
	StatusPass    FindingStatus = "pass"
	StatusFail    FindingStatus = "fail"
	StatusWarn    FindingStatus = "warn"
	StatusError   FindingStatus = "error"
	StatusSkipped FindingStatus = "skipped"
)

// Family groups checks by domain. Open-ended on purpose: third-party
// plugins (post-MVP) may introduce their own families.
type Family string

const (
	FamilyTLS       Family = "tls"
	FamilyHeaders   Family = "headers"
	FamilyCookies   Family = "cookies"
	FamilyDNS       Family = "dns"
	FamilyEmail     Family = "email"
	FamilyWellKnown Family = "wellknown"
	FamilyExposures Family = "exposures"
	FamilyHTTP      Family = "http"
)

// Finding is the unit of output produced by a Check. JSON tags align with
// the OpenAPI Finding schema for direct serialization on the SSE wire.
type Finding struct {
	ID          string         `json:"id"`
	Family      Family         `json:"family"`
	Severity    Severity       `json:"severity"`
	Status      FindingStatus  `json:"status"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	Remediation map[string]any `json:"remediation,omitempty"`
}

// CheckMeta is the static metadata exposed via GET /api/v1/checks. It
// must remain serializable independently of any in-flight scan state.
type CheckMeta struct {
	ID              string   `json:"id"`
	Family          Family   `json:"family"`
	DefaultSeverity Severity `json:"default_severity"`
	Title           string   `json:"title,omitempty"`
	Description     string   `json:"description,omitempty"`
	RFCRefs         []string `json:"rfc_refs,omitempty"`
}
