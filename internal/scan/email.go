package scan

// DNSRecordState describes DNS observations, not email authentication results.
type DNSRecordState string

const (
	DNSRecordObserved    DNSRecordState = "observed"
	DNSRecordAbsent      DNSRecordState = "absent"
	DNSRecordInvalid     DNSRecordState = "invalid"
	DNSRecordUnavailable DNSRecordState = "unavailable"
)

// EmailReport is an informational DNS audit for the selected email domain.
// It is omitted for hosts other than a registrable domain or its www alias.
type EmailReport struct {
	Domain string      `json:"domain"`
	SPF    SPFReport   `json:"spf"`
	DMARC  DMARCReport `json:"dmarc"`
}

// DNSRecord retains the relevant TXT records and configuration diagnostics.
type DNSRecord struct {
	ID         string           `json:"id"`
	State      DNSRecordState   `json:"state"`
	Records    []string         `json:"records"`
	Warnings   []string         `json:"warnings"`
	Assessment *EmailAssessment `json:"assessment,omitempty"`
}

// EmailAssessment explains configuration findings without assigning a mail grade.
type EmailAssessment struct {
	Status          Status   `json:"status"`
	Title           string   `json:"title"`
	Summary         string   `json:"summary"`
	Recommendations []string `json:"recommendations"`
}

// SPFAudit checks static dependencies and counts DNS-causing terms conservatively.
// It does not evaluate a sender, expand macros or resolve address mechanisms.
type SPFAudit struct {
	Complete            bool     `json:"complete"`
	LookupTerms         int      `json:"lookup_terms"`
	LookupLimitExceeded bool     `json:"lookup_limit_exceeded"`
	Queries             []string `json:"queries"`
	Issues              []string `json:"issues"`
	Limitations         []string `json:"limitations"`
}

// SPFReport inspects the policy and static dependencies. All is the first all qualifier.
type SPFReport struct {
	DNSRecord
	All      string    `json:"all,omitempty"`
	Includes []string  `json:"includes"`
	Redirect string    `json:"redirect,omitempty"`
	Audit    *SPFAudit `json:"audit,omitempty"`
}

// DMARCReport describes policy discovery using RFC 9989. Policy is the policy
// for the selected existing domain, after sp selection and testing-mode handling.
type DMARCReport struct {
	DNSRecord
	Policy         string   `json:"policy,omitempty"`
	PolicyDomain   string   `json:"policy_domain,omitempty"`
	PolicyTag      string   `json:"policy_tag,omitempty"`
	Inherited      bool     `json:"inherited"`
	Testing        bool     `json:"testing"`
	Queries        []string `json:"queries"`
	ReportingState string   `json:"reporting_state,omitempty"`
	ReportingURIs  []string `json:"reporting_uris"`
}
