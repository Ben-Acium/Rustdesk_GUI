package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bjones/rustdeskgui/internal/poller"
	"github.com/bjones/rustdeskgui/internal/store"
)

const testPassword = "test-password-123"

func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "app.sqlite3"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// A poller that is never Run: Snapshot() returns the zero value, which is
	// all these handler tests need.
	p := poller.New(poller.Config{Store: st})

	s, err := New(Config{Poller: p, Store: st, PasswordHash: hash, Secret: []byte("test-secret-key")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, s.Handler()
}

// login performs a real login and returns the resulting cookies.
func login(t *testing.T, h http.Handler) []*http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("password="+testPassword))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303; body: %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login set no cookies")
	}
	return cookies
}

func TestUnauthenticatedPageRedirectsToLogin(t *testing.T) {
	_, h := newTestServer(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

// The API must not redirect; a 302 to an HTML page is useless to fetch() and
// hides the real reason from the caller.
func TestUnauthenticatedAPIReturns401(t *testing.T) {
	_, h := newTestServer(t)

	for _, path := range []string{"/api/devices", "/api/devices/123/history"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401", path, rec.Code)
		}
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	_, h := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (re-rendered form)", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Error("a session cookie was issued for a wrong password")
		}
	}
	if !strings.Contains(rec.Body.String(), "Incorrect password") {
		t.Error("response did not report the failure to the user")
	}
}

func TestLoginGrantsAccess(t *testing.T) {
	_, h := newTestServer(t)
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// A tampered signature must not authenticate, or the cookie is decorative.
func TestForgedSessionCookieIsRejected(t *testing.T) {
	_, h := newTestServer(t)
	cookies := login(t, h)

	for _, c := range cookies {
		if c.Name == sessionCookie {
			c.Value = c.Value[:len(c.Value)-4] + "AAAA"
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a forged signature", rec.Code)
	}
}

func TestMetaWriteRequiresCSRFToken(t *testing.T) {
	_, h := newTestServer(t)
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodPost, "/api/devices/123456789/meta",
		strings.NewReader(`{"alias":"pwned"}`))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 without a CSRF token", rec.Code)
	}
}

// With a valid session and CSRF token, an unknown device ID must still be
// refused, so arbitrary IDs cannot seed rows in our store.
func TestMetaWriteRejectsUnknownDevice(t *testing.T) {
	s, h := newTestServer(t)
	cookies := login(t, h)

	var sessionValue string
	for _, c := range cookies {
		if c.Name == sessionCookie {
			sessionValue = c.Value
		}
	}
	payload := sessionValue[:strings.LastIndex(sessionValue, ".")]

	req := httptest.NewRequest(http.MethodPost, "/api/devices/999999999/meta",
		strings.NewReader(`{"alias":"ghost"}`))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", s.sign("csrf:"+payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an unknown device", rec.Code)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	_, h := newTestServer(t)
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not expire the session cookie")
	}
}

func TestSecurityHeadersArePresent(t *testing.T) {
	_, h := newTestServer(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP = %q, want a self-only default-src", csp)
	}
}

func TestHealthEndpointNeedsNoAuth(t *testing.T) {
	_, h := newTestServer(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}
}

// newTestServerWithClient builds a server whose browser client is enabled,
// backed by a throwaway bundle directory.
func newTestServerWithClient(t *testing.T) http.Handler {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("// bundle"), 0o644); err != nil {
		t.Fatalf("writing fake bundle: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "app.sqlite3"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	s, err := New(Config{
		Poller: poller.New(poller.Config{Store: st}), Store: st,
		PasswordHash: hash, Secret: []byte("test-secret-key"),
		WebClient: WebClientConfig{
			Dir: dir, ServerKey: "k",
			IDAddr: "127.0.0.1:21118", RelayAddr: "127.0.0.1:21119",
			PreferCodec: "vp8",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler()
}

// The socket URLs must be same-origin, so that one accepted certificate covers
// the page and its WebSocket together.
func TestClientConfigUsesSameOriginSockets(t *testing.T) {
	h := newTestServerWithClient(t)
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodGet, "/rdclient/config.js", nil)
	req.Host = "10.0.0.1:8443"
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, needle := range []string{
		`wsIdUrl: "ws://10.0.0.1:8443/ws/id"`,
		`wsRelayUrl: "ws://10.0.0.1:8443/ws/relay"`,
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("config.js missing %s:\n%s", needle, body)
		}
	}
	// No upstream address may leak to the browser.
	if strings.Contains(body, "21118") || strings.Contains(body, "21119") {
		t.Errorf("config.js exposes the upstream ports:\n%s", body)
	}
}

func TestClientPageRequiresAuth(t *testing.T) {
	h := newTestServerWithClient(t)

	for _, path := range []string{"/client?id=1", "/rdclient/config.js", "/rdclient/app.js"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusSeeOther && rec.Code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want a redirect or 401", path, rec.Code)
		}
	}
}

// The injected config must carry the server key, or hbbs answers
// LICENSE_MISMATCH and the session never starts.
func TestClientConfigCarriesServerKey(t *testing.T) {
	h := newTestServerWithClient(t)
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodGet, "/rdclient/config.js", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `serverKeyB64: "k"`) {
		t.Errorf("config.js is missing the server key:\n%s", rec.Body)
	}
}

// The proxied sockets are as sensitive as the page: they must not be reachable
// without a session.
func TestWebSocketProxyRequiresAuth(t *testing.T) {
	h := newTestServerWithClient(t)

	for _, path := range []string{"/ws/id", "/ws/relay"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusSeeOther && rec.Code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want a redirect or 401", path, rec.Code)
		}
	}
}

// When the bundle is absent the routes must not exist at all, rather than
// serving a page that cannot work.
func TestClientRoutesAbsentWhenDisabled(t *testing.T) {
	_, h := newTestServer(t)
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodGet, "/client?id=1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when the browser client is disabled", rec.Code)
	}
}

// Regression: the WebSocket upgrade must survive the proxy rewrite.
//
// Go's ReverseProxy only forwards Connection/Upgrade when it recognises the
// inbound request as an upgrade. Losing them turns the handshake into a plain
// GET, which hbbs answers by closing the socket — a bare EOF with nothing to
// suggest why. This asserts the headers reach the upstream, and that the
// session cookie does not.
func TestWebSocketProxyForwardsUpgrade(t *testing.T) {
	type seen struct {
		conn, upgrade, key, realIP, cookie string
	}
	got := make(chan seen, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{
			conn:    r.Header.Get("Connection"),
			upgrade: r.Header.Get("Upgrade"),
			key:     r.Header.Get("Sec-WebSocket-Key"),
			realIP:  r.Header.Get("X-Real-IP"),
			cookie:  r.Header.Get("Cookie"),
		}
		http.Error(w, "not a real websocket server", http.StatusTeapot)
	}))
	defer upstream.Close()

	proxy := newWSProxy(strings.TrimPrefix(upstream.URL, "http://"), slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/ws/id", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Cookie", "rdgui_session=secret")
	// A forged value must not survive; hbbs believes this header.
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.RemoteAddr = "203.0.113.9:51234"

	proxy.ServeHTTP(httptest.NewRecorder(), req)

	select {
	case s := <-got:
		if !strings.EqualFold(s.conn, "Upgrade") {
			t.Errorf("Connection = %q, want Upgrade", s.conn)
		}
		if s.upgrade != "websocket" {
			t.Errorf("Upgrade = %q, want websocket", s.upgrade)
		}
		if s.key == "" {
			t.Error("Sec-WebSocket-Key was dropped")
		}
		if s.realIP != "203.0.113.9" {
			t.Errorf("X-Real-IP = %q, want the observed peer 203.0.113.9 (a forged value must be replaced)", s.realIP)
		}
		if s.cookie != "" {
			t.Errorf("session cookie leaked upstream: %q", s.cookie)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

// The codec seed exists because the device picks AV1 when offered everything,
// and Chrome accepts an AV1 config without reliably rendering the stream.
func TestClientConfigSeedsCodecPreference(t *testing.T) {
	h := newTestServerWithClient(t)
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodGet, "/rdclient/config.js", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `"vp8"`) {
		t.Errorf("config.js does not seed a codec preference:\n%s", body)
	}
	// It must never clobber a choice the user already made.
	if !strings.Contains(body, `getItem(k) === null`) {
		t.Error("the seed is not guarded against overwriting saved preferences")
	}
}

// An unknown codec must be dropped rather than written, since the client would
// discard it anyway and a bad value only muddies debugging.
func TestClientConfigRejectsUnknownCodec(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "app.sqlite3"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("// bundle"), 0o644); err != nil {
		t.Fatalf("writing fake bundle: %v", err)
	}
	hash, _ := HashPassword(testPassword)
	s, err := New(Config{
		Poller: poller.New(poller.Config{Store: st}), Store: st,
		PasswordHash: hash, Secret: []byte("test-secret-key"),
		WebClient: WebClientConfig{
			Dir: dir, ServerKey: "k", IDAddr: "a:1", RelayAddr: "b:2",
			PreferCodec: "jpeg2000",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.Handler()
	cookies := login(t, h)

	req := httptest.NewRequest(http.MethodGet, "/rdclient/config.js", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "jpeg2000") {
		t.Errorf("an unknown codec was written to the client:\n%s", rec.Body)
	}
}

// The files and terminal pages exist so a session can be opened without ever
// requesting the remote screen. They are as sensitive as the desktop page.
func TestStandalonePagesRequireAuth(t *testing.T) {
	h := newTestServerWithClient(t)

	for _, path := range []string{"/files?id=1", "/terminal?id=1"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s status = %d, want a redirect to login", path, rec.Code)
		}
	}
}

func TestStandalonePagesRender(t *testing.T) {
	h := newTestServerWithClient(t)
	cookies := login(t, h)

	cases := []struct{ path, title string }{
		{"/files?id=166378307", "Files"},
		{"/terminal?id=166378307", "Terminal"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", tc.path, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, tc.title) {
			t.Errorf("%s does not name itself %q", tc.path, tc.title)
		}
		// The mount point and bundle the entry needs.
		for _, needle := range []string{`id="rd-standalone"`, "/rdclient/rdgui-standalone.js", "/rdclient/config.js"} {
			if !strings.Contains(body, needle) {
				t.Errorf("%s is missing %s", tc.path, needle)
			}
		}
	}
}

// They are disabled with the rest of the browser client when no bundle exists.
func TestStandalonePagesAbsentWhenDisabled(t *testing.T) {
	_, h := newTestServer(t)
	cookies := login(t, h)

	for _, path := range []string{"/files?id=1", "/terminal?id=1"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404 when the browser client is disabled", path, rec.Code)
		}
	}
}
