package scoring

import (
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

// Per-header weights Their sum is 100 — A+ thresholds use
// HeadersThresholds (this file does not override them).
const (
	weightHSTS        = 20
	weightCSP         = 25
	weightXFO         = 15
	weightXCTO        = 10
	weightReferrer    = 15
	weightPermissions = 15

	bonusCOOPSameOrigin = 5
	bonusCOEP           = 3
	bonusCORP           = 2

	malusServerVersion     = -5
	malusCookieNoSecure    = -5
	malusCookieNoSecureCap = -10
	malusCookieNoHTTPOnly  = -3
	malusCookieNoSameSite  = -3
	malusACAOWildcard      = -10
)

// HeadersFinal computes the final 0–100 score and the matching grade for a
// HeadersReport. Status "pass" earns the full weight, "warn" earns half,
// "fail" earns nothing. Bonuses and maluses are then applied,
// the total is clamped to [0, 100] and mapped through HeadersThresholds.
func HeadersFinal(r *scan.HeadersReport) (int, scan.Grade) {
	score := coreScore(r.Core) + additionalAdjustment(r.Additional)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, HeadersThresholds.Grade(score)
}

func coreScore(core map[string]scan.HeaderResult) int {
	weights := map[string]int{
		"strict-transport-security": weightHSTS,
		"content-security-policy":   weightCSP,
		"x-frame-options":           weightXFO,
		"x-content-type-options":    weightXCTO,
		"referrer-policy":           weightReferrer,
		"permissions-policy":        weightPermissions,
	}
	total := 0
	for name, w := range weights {
		switch core[name].Status {
		case scan.StatusPass:
			total += w
		case scan.StatusWarn:
			total += w / 2
		}
	}
	return total
}

func additionalAdjustment(a scan.AdditionalHeaders) int {
	delta := 0

	if a.CrossOriginOpenerPolicy != nil && a.CrossOriginOpenerPolicy.Status == scan.StatusPass {
		delta += bonusCOOPSameOrigin
	}
	if a.CrossOriginEmbedderPolicy != nil {
		delta += bonusCOEP
	}
	if a.CrossOriginResourcePolicy != nil {
		delta += bonusCORP
	}

	if a.Server != nil && a.Server.Status == scan.StatusWarn {
		delta += malusServerVersion
	}

	delta += cookieAdjustment(a.SetCookie)

	if a.AccessControlAllowOrigin != nil && a.AccessControlAllowOrigin.Status == scan.StatusWarn {
		delta += malusACAOWildcard
	}

	return delta
}

func cookieAdjustment(cookies []scan.CookieResult) int {
	noSecureMalus := 0
	delta := 0
	for _, c := range cookies {
		if !c.Secure {
			noSecureMalus += malusCookieNoSecure
		}
		if c.SameSite == nil {
			delta += malusCookieNoSameSite
		}
		if !c.HTTPOnly && cookieIsSessionLike(c.Name) {
			delta += malusCookieNoHTTPOnly
		}
	}
	if noSecureMalus < malusCookieNoSecureCap {
		noSecureMalus = malusCookieNoSecureCap
	}
	return delta + noSecureMalus
}

// cookieIsSessionLike mirrors headers.LooksLikeSession so scoring can apply
// the HttpOnly malus without depending on the headers package (which would
// pull scan into a cycle through this file).
func cookieIsSessionLike(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range []string{"session", "auth", "token", "sid", "jwt", "csrf"} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}
