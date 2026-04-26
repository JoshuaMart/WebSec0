package http

import (
	"context"

	"github.com/Jomar/websec101/internal/checks"
)

// --- WELLKNOWN-CHANGE-PASSWORD-MISSING --------------------------------
//
// RFC 8615 + the well-known URI registry define `/.well-known/change-
// password` as a redirect target so password managers can take users
// straight to a "change password" UI. A 200 / 301 / 302 / 307 / 308
// is acceptable; a 404 means the well-known is missing.

type changePasswordCheck struct{}

func (changePasswordCheck) ID() string                       { return IDChangePasswordMissing }
func (changePasswordCheck) Family() checks.Family            { return checks.FamilyHTTP }
func (changePasswordCheck) DefaultSeverity() checks.Severity { return checks.SeverityInfo }
func (changePasswordCheck) Title() string                    { return "Site exposes /.well-known/change-password" }
func (changePasswordCheck) Description() string {
	return "Password managers redirect users to this well-known URL when offering a credential change."
}
func (changePasswordCheck) RFCRefs() []string { return []string{"RFC 8615", "W3C Change Password URL"} }

func (changePasswordCheck) Run(ctx context.Context, t *checks.Target) (*checks.Finding, error) {
	res, err := Fetch(ctx, t)
	if err != nil {
		return errFinding(IDChangePasswordMissing, checks.FamilyHTTP, checks.SeverityInfo, err), nil
	}
	if res.ChangePass == nil || res.ChangePass.Err != nil {
		return skipped(IDChangePasswordMissing, checks.FamilyHTTP, checks.SeverityInfo, "probe unreachable"), nil //nolint:nilerr // intentional
	}
	st := res.ChangePass.Status
	switch {
	case st == 200:
		return pass(IDChangePasswordMissing, checks.FamilyHTTP, checks.SeverityInfo,
			"change-password well-known returns 200",
			map[string]any{"status": st}), nil
	case st >= 300 && st < 400:
		return pass(IDChangePasswordMissing, checks.FamilyHTTP, checks.SeverityInfo,
			"change-password well-known redirects",
			map[string]any{"status": st, "location": res.ChangePass.Headers.Get("Location")}), nil
	case st == 404:
		return fail(IDChangePasswordMissing, checks.FamilyHTTP, checks.SeverityInfo,
			"change-password well-known not configured",
			"Redirect `/.well-known/change-password` to your account-settings password page.", nil), nil
	default:
		return fail(IDChangePasswordMissing, checks.FamilyHTTP, checks.SeverityInfo,
			"unexpected status on change-password",
			"Expected 200 or 3xx redirect.",
			map[string]any{"status": st}), nil
	}
}
