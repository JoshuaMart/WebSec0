package headers

import "github.com/JoshuaMart/websec0/internal/checks"

// Register adds every HTTP-headers check to r.
func Register(r *checks.Registry) {
	// CSP
	r.Register(cspMissingCheck{})
	r.Register(cspUnsafeInlineCheck{})
	r.Register(cspUnsafeEvalCheck{})
	r.Register(cspWildcardCheck{})
	r.Register(cspNoObjectSrcCheck{})
	r.Register(cspNoBaseURICheck{})
	r.Register(cspNoFrameAncestorsCheck{})

	// Core security headers
	r.Register(xctoCheck{})
	r.Register(xfoCheck{})
	r.Register(referrerPolicyMissingCheck{})
	r.Register(referrerPolicyUnsafeCheck{})
	r.Register(permissionsPolicyMissingCheck{})
	r.Register(featurePolicyDeprecatedCheck{})
	r.Register(coopCheck{})
	r.Register(coepCheck{})
	r.Register(corpCheck{})
	r.Register(reportingEndpointsCheck{})
	r.Register(nelCheck{})

	// Deprecated / harmful
	r.Register(xssProtectionCheck{})
	r.Register(hpkpCheck{})
	r.Register(expectCTCheck{})

	// Info disclosure
	r.Register(newInfoServer())
	r.Register(newInfoXPoweredBy())
	r.Register(newInfoXAspNetVersion())
	r.Register(newInfoXGenerator())
	r.Register(newInfoServerTiming())
}
