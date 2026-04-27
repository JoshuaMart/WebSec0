package email

import "github.com/JoshuaMart/websec0/internal/checks"

// Register adds every email check to r. The MX-gating logic lives inside
// each check (gateOnMX), so domains without MX skip every check cleanly.
func Register(r *checks.Registry) {
	r.Register(spfMissingCheck{})
	r.Register(spfMultipleCheck{})
	r.Register(spfInvalidSyntaxCheck{})
	r.Register(spfNoAllCheck{})
	r.Register(spfPassAllCheck{})
	r.Register(spfSoftfailAllCheck{})
	r.Register(spfPTRCheck{})

	r.Register(dkimNoneFoundCheck{})
	r.Register(dkimWeakKeyCheck{})
	r.Register(dkimSHA1Check{})
	r.Register(dkimTestModeCheck{})

	r.Register(dmarcMissingCheck{})
	r.Register(dmarcInvalidSyntaxCheck{})
	r.Register(dmarcPolicyNoneCheck{})
	r.Register(dmarcPolicyWeakCheck{})
	r.Register(dmarcNoRUACheck{})

	r.Register(mtastsMissingCheck{})
	r.Register(mtastsModeTestingCheck{})
	r.Register(mtastsMaxAgeLowCheck{})

	r.Register(tlsrptMissingCheck{})
	r.Register(bimiMissingCheck{})
}
