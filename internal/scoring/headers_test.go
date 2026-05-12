package scoring

import (
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func headersReportFromStatuses(statuses map[string]scan.Status) *scan.HeadersReport {
	core := map[string]scan.HeaderResult{}
	for k, v := range statuses {
		core[k] = scan.HeaderResult{Status: v, Present: v != scan.StatusFail}
	}
	return &scan.HeadersReport{Core: core}
}

func TestHeadersFinal_AllPassYieldsAPlus(t *testing.T) {
	r := headersReportFromStatuses(map[string]scan.Status{
		"strict-transport-security": scan.StatusPass,
		"content-security-policy":   scan.StatusPass,
		"x-frame-options":           scan.StatusPass,
		"x-content-type-options":    scan.StatusPass,
		"referrer-policy":           scan.StatusPass,
		"permissions-policy":        scan.StatusPass,
	})
	score, grade := HeadersFinal(r)
	if score != 100 {
		t.Errorf("score: got %d, want 100", score)
	}
	if grade != scan.GradeAPlus {
		t.Errorf("grade: got %s, want A+", grade)
	}
}

func TestHeadersFinal_AllFailYieldsF(t *testing.T) {
	r := headersReportFromStatuses(map[string]scan.Status{
		"strict-transport-security": scan.StatusFail,
		"content-security-policy":   scan.StatusFail,
		"x-frame-options":           scan.StatusFail,
		"x-content-type-options":    scan.StatusFail,
		"referrer-policy":           scan.StatusFail,
		"permissions-policy":        scan.StatusFail,
	})
	score, grade := HeadersFinal(r)
	if score != 0 {
		t.Errorf("score: got %d, want 0", score)
	}
	if grade != scan.GradeF {
		t.Errorf("grade: got %s, want F", grade)
	}
}

func TestHeadersFinal_WarnGivesHalfWeight(t *testing.T) {
	r := headersReportFromStatuses(map[string]scan.Status{
		"strict-transport-security": scan.StatusWarn, // weight 20 → 10
		"content-security-policy":   scan.StatusPass, // weight 25
		"x-frame-options":           scan.StatusPass, // weight 15
		"x-content-type-options":    scan.StatusPass, // weight 10
		"referrer-policy":           scan.StatusPass, // weight 15
		"permissions-policy":        scan.StatusPass, // weight 15
	})
	score, _ := HeadersFinal(r)
	if score != 90 {
		t.Errorf("score: got %d, want 90 (10+25+15+10+15+15)", score)
	}
}

func TestHeadersFinal_ServerVersionLeakDeducts(t *testing.T) {
	r := headersReportFromStatuses(map[string]scan.Status{
		"strict-transport-security": scan.StatusPass,
		"content-security-policy":   scan.StatusPass,
		"x-frame-options":           scan.StatusPass,
		"x-content-type-options":    scan.StatusPass,
		"referrer-policy":           scan.StatusPass,
		"permissions-policy":        scan.StatusPass,
	})
	r.Additional.Server = &scan.HeaderResult{Status: scan.StatusWarn, Value: "nginx/1.27"}
	score, _ := HeadersFinal(r)
	if score != 95 {
		t.Errorf("score: got %d, want 95 (100 - 5 for Server leak)", score)
	}
}

func TestHeadersFinal_ClampsAtHundredWithBonus(t *testing.T) {
	r := headersReportFromStatuses(map[string]scan.Status{
		"strict-transport-security": scan.StatusPass,
		"content-security-policy":   scan.StatusPass,
		"x-frame-options":           scan.StatusPass,
		"x-content-type-options":    scan.StatusPass,
		"referrer-policy":           scan.StatusPass,
		"permissions-policy":        scan.StatusPass,
	})
	r.Additional.CrossOriginOpenerPolicy = &scan.HeaderResult{Status: scan.StatusPass}
	r.Additional.CrossOriginEmbedderPolicy = &scan.HeaderResult{Status: scan.StatusPass}
	r.Additional.CrossOriginResourcePolicy = &scan.HeaderResult{Status: scan.StatusPass}
	score, _ := HeadersFinal(r)
	if score != 100 {
		t.Errorf("score: got %d, want 100 (clamped from 110)", score)
	}
}

func TestHeadersFinal_CookieNoSecureCapped(t *testing.T) {
	r := headersReportFromStatuses(map[string]scan.Status{
		"strict-transport-security": scan.StatusPass,
		"content-security-policy":   scan.StatusPass,
		"x-frame-options":           scan.StatusPass,
		"x-content-type-options":    scan.StatusPass,
		"referrer-policy":           scan.StatusPass,
		"permissions-policy":        scan.StatusPass,
	})
	// Five insecure cookies. -5 each would be -25, but capped at -10.
	for i := 0; i < 5; i++ {
		ss := "Strict"
		r.Additional.SetCookie = append(r.Additional.SetCookie, scan.CookieResult{
			Name:     "id",
			Secure:   false,
			SameSite: &ss,
			HTTPOnly: true,
			Status:   scan.StatusFail,
		})
	}
	score, _ := HeadersFinal(r)
	if score != 90 {
		t.Errorf("score: got %d, want 90 (100 - 10 cap)", score)
	}
}

func TestHeadersFinal_ACAOWildcardDeducts(t *testing.T) {
	r := headersReportFromStatuses(map[string]scan.Status{
		"strict-transport-security": scan.StatusPass,
		"content-security-policy":   scan.StatusPass,
		"x-frame-options":           scan.StatusPass,
		"x-content-type-options":    scan.StatusPass,
		"referrer-policy":           scan.StatusPass,
		"permissions-policy":        scan.StatusPass,
	})
	r.Additional.AccessControlAllowOrigin = &scan.HeaderResult{Status: scan.StatusWarn, Value: "*"}
	score, _ := HeadersFinal(r)
	if score != 90 {
		t.Errorf("score: got %d, want 90 (100 - 10 ACAO wildcard)", score)
	}
}
