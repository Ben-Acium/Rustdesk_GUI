// Package web serves the fleet UI: a login page and a device list, backed by
// the poller's in-memory snapshot.
package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bjones/rustdeskgui/internal/intel"
	"github.com/bjones/rustdeskgui/internal/poller"
	"github.com/bjones/rustdeskgui/internal/store"
)

//go:embed all:templates all:static
var assets embed.FS

const sessionTTL = 12 * time.Hour

// maxFieldLen bounds alias and note so a stored value cannot bloat the page.
const (
	maxAliasLen = 64
	maxNoteLen  = 1000
)

type Server struct {
	poller *poller.Poller
	store  *store.Store
	log    *slog.Logger

	passwordHash string
	secret       []byte
	tmpl         *template.Template
	webClient    WebClientConfig
	// vault seals saved device credentials. Disabled unless a key is set, in
	// which case the whole "remember this password" feature stays off.
	vault *vault
	// locator turns a device's address into a coarse location for its Intel
	// report. Disabled unless an endpoint is configured.
	locator *intel.Locator
	// insecureCookies drops the Secure flag so one session works across both
	// the HTTPS and plain-HTTP listeners. Set only when an HTTP listener runs.
	insecureCookies bool

	// Login throttle. One account, so a single counter is enough; it exists to
	// make online guessing impractical, not to be a general rate limiter.
	loginMu       sync.Mutex
	loginFailures int
	loginBlocked  time.Time
}

type Config struct {
	Poller       *poller.Poller
	Store        *store.Store
	PasswordHash string
	Secret       []byte
	Logger       *slog.Logger
	WebClient    WebClientConfig
	// SecretKey is the base64 32-byte key for saved device credentials. Empty
	// disables the feature rather than failing: it is opt-in.
	SecretKey string
	// GeoURL is the endpoint Intel uses to locate a device's address, with an
	// {ip} placeholder. Empty disables location lookups.
	GeoURL string
	// InsecureCookies drops the session cookie's Secure flag. Required when a
	// plain-HTTP listener is enabled, otherwise the cookie set over HTTPS is
	// never sent to it.
	InsecureCookies bool
}

func New(c Config) (*Server, error) {
	tmpl, err := template.New("").Funcs(templateFuncs()).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	v, err := newVault(c.SecretKey)
	if err != nil {
		return nil, err
	}
	loc, err := intel.NewLocator(c.GeoURL)
	if err != nil {
		return nil, err
	}
	return &Server{
		poller: c.Poller, store: c.Store, log: c.Logger,
		passwordHash: c.PasswordHash, secret: c.Secret, tmpl: tmpl,
		webClient: c.WebClient, vault: v, locator: loc,
		insecureCookies: c.InsecureCookies,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.Handle("GET /static/", http.FileServerFS(assets))

	mux.HandleFunc("GET /{$}", s.requireAuth(s.handleIndex))
	mux.HandleFunc("GET /device/{id}", s.requireAuth(s.handleDevicePage))
	mux.HandleFunc("GET /api/devices", s.requireAuthAPI(s.handleDevices))
	mux.HandleFunc("POST /api/devices/{id}/meta", s.requireAuthAPI(s.handleSetMeta))
	mux.HandleFunc("GET /api/devices/{id}/history", s.requireAuthAPI(s.handleHistory))
	mux.HandleFunc("PUT /api/devices/{id}/secret", s.requireAuthAPI(s.handleSaveSecret))
	mux.HandleFunc("DELETE /api/devices/{id}/secret", s.requireAuthAPI(s.handleForgetSecret))
	mux.HandleFunc("GET /api/devices/{id}/probe", s.requireAuthAPI(s.handleProbe))
	mux.HandleFunc("GET /api/devices/{id}/intel", s.requireAuthAPI(s.handleGetIntel))
	mux.HandleFunc("PUT /api/devices/{id}/intel", s.requireAuthAPI(s.handlePutIntel))
	mux.HandleFunc("DELETE /api/devices/{id}/intel", s.requireAuthAPI(s.handleDeleteIntel))
	mux.HandleFunc("POST /api/devices/{id}/archive", s.requireAuthAPI(s.handleArchive))
	mux.HandleFunc("DELETE /api/devices/{id}", s.requireAuthAPI(s.handleForgetDevice))
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// The browser client and its bundle sit behind the same session as the
	// device list; the bundle is only served when it is actually present.
	if s.webClient.Enabled() {
		mux.HandleFunc("GET /client", s.requireAuth(s.handleClient))
		mux.HandleFunc("GET /rdclient/config.js", s.requireAuth(s.handleClientConfig))
		mux.HandleFunc("GET /rdclient/logo.png", s.requireAuth(s.handleClientLogo))
		mux.HandleFunc("GET /files", s.requireAuth(s.handleStandalone("files")))
		mux.HandleFunc("GET /terminal", s.requireAuth(s.handleStandalone("terminal")))

		// The rendezvous and relay sockets are proxied through this origin so
		// the page's certificate covers them too; see newWSProxy.
		idProxy := newWSProxy(s.webClient.IDAddr, s.log)
		relayProxy := newWSProxy(s.webClient.RelayAddr, s.log)
		mux.Handle("/ws/id", s.requireAuth(idProxy.ServeHTTP))
		mux.Handle("/ws/relay", s.requireAuth(relayProxy.ServeHTTP))
		mux.Handle("GET /rdclient/", s.requireAuth(s.handleClientAssets().ServeHTTP))
	}

	return securityHeaders(mux)
}

// securityHeaders applies a restrictive CSP. The UI ships no third-party assets,
// so 'self' is sufficient and inline script is not needed.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		switch {
		case strings.HasPrefix(r.URL.Path, "/client"),
			strings.HasPrefix(r.URL.Path, "/device/"),
			strings.HasPrefix(r.URL.Path, "/files"),
			strings.HasPrefix(r.URL.Path, "/terminal"),
			strings.HasPrefix(r.URL.Path, "/rdclient/"),
			strings.HasPrefix(r.URL.Path, "/ws/"):
			// These set their own policy; see WebClientConfig.csp.
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			next.ServeHTTP(w, r)
			return
		}
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			writeJSONError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if s.authenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", map[string]any{"Error": ""})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, "login.html", map[string]any{"Error": "Malformed request."})
		return
	}

	if wait, blocked := s.loginThrottle(); blocked {
		s.render(w, "login.html", map[string]any{
			"Error": "Too many attempts. Try again in " + wait.Round(time.Second).String() + ".",
		})
		return
	}

	if !VerifyPassword(r.PostFormValue("password"), s.passwordHash) {
		s.noteLoginFailure()
		s.log.Warn("failed login", "remote", clientIP(r))
		// A uniform delay on failure, on top of argon2's own cost.
		time.Sleep(300 * time.Millisecond)
		s.render(w, "login.html", map[string]any{"Error": "Incorrect password."})
		return
	}

	s.noteLoginSuccess()
	if err := s.issueSession(w, r, sessionTTL); err != nil {
		s.log.Error("issuing session failed", "error", err)
		s.render(w, "login.html", map[string]any{"Error": "Could not start a session."})
		return
	}
	s.log.Info("login succeeded", "remote", clientIP(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) loginThrottle() (time.Duration, bool) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if time.Now().Before(s.loginBlocked) {
		return time.Until(s.loginBlocked), true
	}
	return 0, false
}

func (s *Server) noteLoginFailure() {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.loginFailures++
	if s.loginFailures >= 5 {
		s.loginBlocked = time.Now().Add(time.Minute)
		s.loginFailures = 0
	}
}

func (s *Server) noteLoginSuccess() {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.loginFailures = 0
	s.loginBlocked = time.Time{}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	snap := s.poller.Snapshot()
	csrf := ""
	if payload, ok := s.sessionPayload(r); ok {
		csrf = s.sign("csrf:" + payload)
	}
	s.render(w, "index.html", map[string]any{
		"Snapshot": snap,
		// What the list actually shows: archived devices are hidden behind
		// their own toggle and counted there instead.
		"Total":     len(snap.Devices) - snap.Archived,
		"CSRF":      csrf,
		"WebClient": s.webClient.Enabled(),
		"Saved":     s.savedSecretIDs(r),
		"CanSave":   s.vault.enabled(),
		"HasIntel":  s.hasIntel(r),
	})
}

// devicesResponse is the poller's snapshot plus which devices have a saved
// credential. The poller has no business knowing about credentials, so the two
// are joined here rather than in the snapshot itself.
type devicesResponse struct {
	poller.Snapshot
	Saved   map[string]bool      `json:"saved"`
	CanSave bool                 `json:"can_save"`
	Intel   map[string]time.Time `json:"intel"`
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	saved := s.savedSecretIDs(r)
	if saved == nil {
		saved = map[string]bool{}
	}
	collected := s.intelAges(r)
	if collected == nil {
		collected = map[string]time.Time{}
	}
	writeJSON(w, http.StatusOK, devicesResponse{
		Snapshot: s.poller.Snapshot(),
		Saved:    saved,
		CanSave:  s.vault.enabled(),
		Intel:    collected,
	})
}

// hasIntel reports which devices have been collected, for the list's marker.
// The template needs a plain boolean: a zero time.Time from a missing map key
// is still a struct, which `if` would treat as present.
func (s *Server) hasIntel(r *http.Request) map[string]bool {
	out := make(map[string]bool)
	for id := range s.intelAges(r) {
		out[id] = true
	}
	return out
}

// intelAges reports when each device was last collected. It reads no reports:
// the list shows only how stale each one is.
func (s *Server) intelAges(r *http.Request) map[string]time.Time {
	ages, err := s.store.IntelCollectedAt(r.Context())
	if err != nil {
		s.log.Error("listing intel timestamps failed", "error", err)
		return nil
	}
	return ages
}

func (s *Server) handleSetMeta(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}

	var body struct {
		Alias string `json:"alias"`
		Note  string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body")
		return
	}

	m := store.Meta{
		Alias: truncate(strings.TrimSpace(body.Alias), maxAliasLen),
		Note:  truncate(strings.TrimSpace(body.Note), maxNoteLen),
	}
	if err := s.store.SetMeta(r.Context(), id, m); err != nil {
		s.log.Error("saving device meta failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not save")
		return
	}

	// Refresh so the next poll interval does not show stale labels.
	if err := s.poller.Poll(r.Context()); err != nil {
		s.log.Warn("refresh after meta change failed", "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alias": m.Alias, "note": m.Note})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}

	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := time.ParseDuration(v + "h"); err == nil && n > 0 {
			days = int(n.Hours())
		}
	}
	if days > 90 {
		days = 90
	}
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	events, err := s.store.History(r.Context(), id, since)
	if err != nil {
		s.log.Error("reading history failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not read history")
		return
	}

	// A nil slice marshals to null; callers expect a list.
	if events == nil {
		events = []store.Event{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id": id,
		"since":   since.UTC(),
		"events":  events,
		"uptime":  uptimeFraction(events, since, time.Now().UTC(), s.currentOnline(id)),
	})
}

// knownDevice guards the write and history paths so arbitrary IDs cannot be
// used to create rows in our store.
func (s *Server) knownDevice(id string) bool {
	for _, d := range s.poller.Snapshot().Devices {
		if d.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) currentOnline(id string) bool {
	for _, d := range s.poller.Snapshot().Devices {
		if d.ID == id {
			return d.Online
		}
	}
	return false
}

// uptimeFraction computes the share of the window a device spent online, by
// walking the transition log. The state before the first recorded event is
// inferred from the first event itself: if the device first went offline, it
// must have been online until then.
func uptimeFraction(events []store.Event, since, until time.Time, nowOnline bool) float64 {
	window := until.Sub(since).Seconds()
	if window <= 0 {
		return 0
	}

	state := nowOnline
	if len(events) > 0 {
		state = !events[0].Online
	}

	var onlineSecs float64
	cursor := since
	for _, e := range events {
		if e.At.Before(cursor) {
			continue
		}
		if state {
			onlineSecs += e.At.Sub(cursor).Seconds()
		}
		state = e.Online
		cursor = e.At
	}
	if state {
		onlineSecs += until.Sub(cursor).Seconds()
	}
	return onlineSecs / window
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("rendering template failed", "template", name, "error", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func clientIP(r *http.Request) string {
	host, _, found := strings.Cut(r.RemoteAddr, ":")
	if !found {
		return r.RemoteAddr
	}
	return host
}
