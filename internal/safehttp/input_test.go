package safehttp

import (
	"errors"
	"testing"
)

var stdPolicy = InputPolicy{
	AllowedSchemes: []string{"https"},
	DefaultPort:    443,
}

func TestValidateInput_AcceptedForms(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"example.com", "example.com", 443},
		{"https://example.com", "example.com", 443},
		{"HTTPS://Example.COM", "example.com", 443},
		{"example.com.", "example.com", 443},
		{"sub.example.com", "sub.example.com", 443},
		{"xn--mnchen-3ya.de", "xn--mnchen-3ya.de", 443},
		{"https://example.com/path?q=1#frag", "example.com", 443},
	}
	for _, c := range cases {
		v, err := ValidateInput(c.in, stdPolicy)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if v.Host != c.wantHost || v.Port != c.wantPort {
			t.Errorf("%q: got host=%s port=%d, want %s %d", c.in, v.Host, v.Port, c.wantHost, c.wantPort)
		}
	}
}

func TestValidateInput_RejectsBadSchemes(t *testing.T) {
	for _, in := range []string{"http://example.com", "ftp://example.com", "gopher://example.com", "file:///etc/passwd"} {
		_, err := ValidateInput(in, stdPolicy)
		if !errors.Is(err, ErrInvalidScheme) {
			t.Errorf("%q: expected ErrInvalidScheme, got %v", in, err)
		}
	}
}

func TestValidateInput_RejectsIPLiterals(t *testing.T) {
	for _, in := range []string{
		"192.168.1.1", "10.0.0.1", "8.8.8.8",
		"https://1.1.1.1", "https://[::1]/", "https://[2001:db8::1]:8443",
	} {
		_, err := ValidateInput(in, stdPolicy)
		if !errors.Is(err, ErrIPLiteral) {
			t.Errorf("%q: expected ErrIPLiteral, got %v", in, err)
		}
	}
}

func TestValidateInput_RejectsUserinfo(t *testing.T) {
	_, err := ValidateInput("https://user:pass@example.com", stdPolicy)
	if !errors.Is(err, ErrUserInfo) {
		t.Errorf("expected ErrUserInfo, got %v", err)
	}
}

func TestValidateInput_RejectsInvalidFQDN(t *testing.T) {
	for _, in := range []string{
		"", "   ",
		"example",                     // no dot
		"-bad.example.com",            // label starts with hyphen
		"bad-.example.com",            // label ends with hyphen
		".example.com",                // empty leading label
		"example..com",                // empty middle label
		"münchen.de",                  // raw Unicode (must be pre-punycoded)
		"a." + longLabel(64) + ".com", // label too long
	} {
		_, err := ValidateInput(in, stdPolicy)
		if err == nil {
			t.Errorf("%q: expected error, got nil", in)
		}
	}
}

func longLabel(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestValidateInput_CustomPortPolicy(t *testing.T) {
	deny := InputPolicy{AllowedSchemes: []string{"https"}, DefaultPort: 443}
	if _, err := ValidateInput("https://example.com:8443", deny); !errors.Is(err, ErrCustomPortBlocked) {
		t.Errorf("expected ErrCustomPortBlocked, got %v", err)
	}
	allow := InputPolicy{AllowedSchemes: []string{"https"}, DefaultPort: 443, AllowCustomPorts: true}
	v, err := ValidateInput("https://example.com:8443", allow)
	if err != nil {
		t.Fatal(err)
	}
	if v.Port != 8443 {
		t.Errorf("got port %d, want 8443", v.Port)
	}
}

func TestValidateInput_RejectsBadPort(t *testing.T) {
	allow := InputPolicy{AllowedSchemes: []string{"https"}, DefaultPort: 443, AllowCustomPorts: true}
	for _, in := range []string{"https://example.com:0", "https://example.com:99999", "https://example.com:-1"} {
		if _, err := ValidateInput(in, allow); err == nil {
			t.Errorf("%q: expected error, got nil", in)
		}
	}
}
