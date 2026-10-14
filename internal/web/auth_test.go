package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bjones/rustdeskgui/internal/store"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash = %q, want an argon2id PHC string", hash)
	}
	if !VerifyPassword("correct horse battery staple", hash) {
		t.Error("correct password rejected")
	}
	if VerifyPassword("wrong password", hash) {
		t.Error("wrong password accepted")
	}
	if VerifyPassword("", hash) {
		t.Error("empty password accepted")
	}
}

// Two hashes of the same password must differ, or the salt is not doing its job.
func TestHashPasswordIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Error("two hashes of the same password are identical; salt is not random")
	}
}

// A malformed or empty configured hash must reject every password rather than
// failing open.
func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$m=65536,t=3,p=2$onlyonefield",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA",  // wrong variant
		"$argon2id$v=16$m=65536,t=3,p=2$c2FsdA$aGFzaA", // wrong version
		"$argon2id$v=19$m=65536,t=3,p=2$!!!$aGFzaA",    // bad base64
	} {
		if VerifyPassword("anything", bad) {
			t.Errorf("malformed hash %q accepted a password", bad)
		}
	}
}

func TestUptimeFraction(t *testing.T) {
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := since.Add(10 * time.Hour)

	cases := []struct {
		name      string
		events    []store.Event
		nowOnline bool
		want      float64
	}{
		{
			name:      "no events, currently online means online throughout",
			nowOnline: true,
			want:      1,
		},
		{
			name:      "no events, currently offline means offline throughout",
			nowOnline: false,
			want:      0,
		},
		{
			// First recorded event is "went offline", so it was up until then.
			name:   "went offline halfway",
			events: []store.Event{{Online: false, At: since.Add(5 * time.Hour)}},
			want:   0.5,
		},
		{
			// First recorded event is "came online", so it was down until then.
			name:      "came online halfway",
			events:    []store.Event{{Online: true, At: since.Add(5 * time.Hour)}},
			nowOnline: true,
			want:      0.5,
		},
		{
			name: "up, down, up",
			events: []store.Event{
				{Online: false, At: since.Add(2 * time.Hour)},
				{Online: true, At: since.Add(6 * time.Hour)},
			},
			want: 0.6, // 2h up + 4h down + 4h up
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := uptimeFraction(tc.events, since, until, tc.nowOnline)
			if diff := got - tc.want; diff > 0.001 || diff < -0.001 {
				t.Errorf("uptimeFraction = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUptimeFractionHandlesZeroWindow(t *testing.T) {
	now := time.Now()
	if got := uptimeFraction(nil, now, now, true); got != 0 {
		t.Errorf("zero-length window returned %v, want 0", got)
	}
}

func TestFormatID(t *testing.T) {
	cases := map[string]string{
		"123456789":  "123 456 789",
		"1234567890": "1 234 567 890",
		"12345":      "12345",
		"":           "",
	}
	for in, want := range cases {
		if got := formatID(in); got != want {
			t.Errorf("formatID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc" {
		t.Errorf("truncate = %q, want abc", got)
	}
	if got := truncate("ab", 10); got != "ab" {
		t.Errorf("truncate = %q, want ab", got)
	}
}

// The page and its sockets share one origin, so links are relative and one
// accepted certificate covers both.
func TestWebClientPageURL(t *testing.T) {
	c := WebClientConfig{}
	if got, want := c.PageURL("166378307"), "/client?id=166378307"; got != want {
		t.Errorf("PageURL = %q, want %q", got, want)
	}
}

// The bundle instantiates inlined WASM and paints from a worker, so the client
// page needs a policy the site-wide one deliberately does not grant.
func TestWebClientCSPAllowsWasmAndItsSockets(t *testing.T) {
	csp := WebClientConfig{}.csp()
	for _, needle := range []string{
		"'wasm-unsafe-eval'",
		"worker-src 'self' blob:",
		// The socket is proxied through this origin, so 'self' must cover it
		// and no upstream host may need naming.
		"connect-src 'self'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, needle) {
			t.Errorf("CSP missing %q:\n%s", needle, csp)
		}
	}
}

// A missing bundle must disable the feature, not crash or serve a broken page.
func TestWebClientDisabledWithoutBundle(t *testing.T) {
	cases := []WebClientConfig{
		{},
		{Dir: "/nonexistent", ServerKey: "k", IDAddr: "a", RelayAddr: "b"},
		{Dir: t.TempDir(), ServerKey: "k", IDAddr: "a", RelayAddr: "b"}, // no app.js
		{Dir: t.TempDir(), ServerKey: "", IDAddr: "a", RelayAddr: "b"},  // no server key
		{Dir: t.TempDir(), ServerKey: "k", IDAddr: "", RelayAddr: "b"},  // no upstream
	}
	for i, c := range cases {
		if c.Enabled() {
			t.Errorf("case %d: Enabled() = true, want false", i)
		}
	}
}

// wsOrigin decides whether the client is told ws:// or wss://, which has to
// follow the request rather than any configured value.
func TestWSOriginFollowsTheRequest(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "/rdclient/config.js", nil)
	plain.Host = "10.0.0.1:8443"
	if got, want := wsOrigin(plain), "ws://10.0.0.1:8443"; got != want {
		t.Errorf("wsOrigin = %q, want %q", got, want)
	}

	secure := httptest.NewRequest(http.MethodGet, "/rdclient/config.js", nil)
	secure.Host = "10.0.0.1:8443"
	secure.TLS = &tls.ConnectionState{}
	if got, want := wsOrigin(secure), "wss://10.0.0.1:8443"; got != want {
		t.Errorf("wsOrigin = %q, want %q", got, want)
	}
}
