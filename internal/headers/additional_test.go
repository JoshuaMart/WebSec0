package headers

import (
	"net/http"
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestEvaluateAdditional_Server(t *testing.T) {
	t.Run("version leak", func(t *testing.T) {
		h := http.Header{"Server": []string{"nginx/1.27.1"}}
		out := EvaluateAdditional(h)
		if out.Server == nil || out.Server.Status != scan.StatusWarn {
			t.Errorf("expected warn, got %+v", out.Server)
		}
	})
	t.Run("opaque server", func(t *testing.T) {
		h := http.Header{"Server": []string{"cloudflare"}}
		out := EvaluateAdditional(h)
		if out.Server == nil || out.Server.Status != scan.StatusInfo {
			t.Errorf("expected info, got %+v", out.Server)
		}
	})
}

func TestEvaluateAdditional_CrossOrigin(t *testing.T) {
	h := http.Header{
		"Cross-Origin-Opener-Policy":   []string{"same-origin"},
		"Cross-Origin-Embedder-Policy": []string{"require-corp"},
		"Cross-Origin-Resource-Policy": []string{"same-site"},
	}
	out := EvaluateAdditional(h)
	if out.CrossOriginOpenerPolicy == nil || out.CrossOriginOpenerPolicy.Status != scan.StatusPass {
		t.Errorf("COOP: %+v", out.CrossOriginOpenerPolicy)
	}
	if out.CrossOriginEmbedderPolicy == nil {
		t.Error("COEP missing")
	}
	if out.CrossOriginResourcePolicy == nil {
		t.Error("CORP missing")
	}
}

func TestEvaluateAdditional_Cookies(t *testing.T) {
	h := http.Header{
		"Set-Cookie": []string{
			"session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
			"tracker=xyz",
		},
	}
	out := EvaluateAdditional(h)
	if len(out.SetCookie) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(out.SetCookie))
	}
	if out.SetCookie[0].Status != scan.StatusPass {
		t.Errorf("session cookie: got %s, want pass", out.SetCookie[0].Status)
	}
	if out.SetCookie[1].Status != scan.StatusFail {
		t.Errorf("tracker cookie (no Secure): got %s, want fail", out.SetCookie[1].Status)
	}
	if out.SetCookie[1].Secure {
		t.Error("tracker cookie.Secure should be false")
	}
}

func TestEvaluateAdditional_ACAOWildcard(t *testing.T) {
	h := http.Header{"Access-Control-Allow-Origin": []string{"*"}}
	out := EvaluateAdditional(h)
	if out.AccessControlAllowOrigin == nil || out.AccessControlAllowOrigin.Status != scan.StatusWarn {
		t.Errorf("expected warn, got %+v", out.AccessControlAllowOrigin)
	}
}

func TestLooksLikeSession(t *testing.T) {
	for _, n := range []string{"session", "JSESSIONID", "auth_token", "csrfToken", "user_jwt", "sid"} {
		if !LooksLikeSession(n) {
			t.Errorf("%q should look session-like", n)
		}
	}
	for _, n := range []string{"tracker", "pref", "lang", "ab_test"} {
		if LooksLikeSession(n) {
			t.Errorf("%q should not look session-like", n)
		}
	}
}
