package safehttp

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCappedReader_Boundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		tooLarge bool
	}{
		{"empty", "", false},
		{"below", "abc", false},
		{"exact", "abcd", false},
		{"above", "abcde", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &cappedReader{r: io.NopCloser(strings.NewReader(tc.body)), remaining: 4}
			body, err := io.ReadAll(r)
			if errors.Is(err, ErrBodyTooLarge) != tc.tooLarge || (!tc.tooLarge && err != nil) {
				t.Fatalf("ReadAll: %q, %v", body, err)
			}
			if string(body) != tc.body[:min(len(tc.body), 4)] {
				t.Fatalf("unexpected body: %q", body)
			}
			if tc.tooLarge {
				if _, err := r.Read(make([]byte, 1)); !errors.Is(err, ErrBodyTooLarge) {
					t.Fatalf("overflow error was not preserved: %v", err)
				}
			}
			if n, err := r.Read(nil); n != 0 || err != nil {
				t.Fatalf("zero-length read: %d, %v", n, err)
			}
		})
	}
}

func TestNewClient_CloseIdleConnections(t *testing.T) {
	for _, capBytes := range []int64{0, 1024} {
		for _, http2 := range []bool{false, true} {
			t.Run(fmtTestClient(capBytes, http2), func(t *testing.T) {
				closed := make(chan struct{}, 1)
				srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(w, "ok")
				}))
				srv.EnableHTTP2 = http2
				srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						select {
						case closed <- struct{}{}:
						default:
						}
					}
				}
				srv.StartTLS()
				defer srv.Close()
				target := targetFor(t, srv.URL, "example.test")
				client := NewClient(ClientOpts{Target: target, MaxBodyBytes: capBytes})
				defer client.CloseIdleConnections()
				resp, err := client.Get(target.URL("/"))
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if (resp.ProtoMajor == 2) != http2 {
					t.Fatalf("unexpected protocol %s", resp.Proto)
				}
				client.CloseIdleConnections()
				select {
				case <-closed:
				case <-time.After(2 * time.Second):
					t.Fatal("idle connection was not closed")
				}
			})
		}
	}
}

func fmtTestClient(capBytes int64, http2 bool) string {
	name := "uncapped"
	if capBytes > 0 {
		name = "capped"
	}
	if http2 {
		return name + "/h2"
	}
	return name + "/h1"
}
