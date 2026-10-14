package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for the single admin password. Deliberately costly: this
// hash is verified at most a few times a day, so there is no reason to be cheap.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

const (
	sessionCookie = "rdgui_session"
	csrfCookie    = "rdgui_csrf"
)

var errBadHashFormat = errors.New("password hash is not a valid argon2id PHC string")

// HashPassword produces a PHC-format argon2id string for the `hash` subcommand.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC-format argon2id hash.
//
// It always performs the full key derivation, even when the hash is malformed,
// so a bad configuration cannot be distinguished from a wrong password by
// response timing.
func VerifyPassword(password, encoded string) bool {
	salt, want, time_, memory, threads, err := parseArgon2Hash(encoded)
	if err != nil {
		// Burn comparable work against a dummy salt, then fail.
		argon2.IDKey([]byte(password), make([]byte, argonSaltLen), argonTime, argonMemory, argonThreads, argonKeyLen)
		return false
	}
	got := argon2.IDKey([]byte(password), salt, time_, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseArgon2Hash(encoded string) (salt, key []byte, time_ uint32, memory uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, errBadHashFormat
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, nil, 0, 0, 0, errBadHashFormat
	}

	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, errBadHashFormat
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, nil, 0, 0, 0, errBadHashFormat
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return nil, nil, 0, 0, 0, errBadHashFormat
	}
	if len(salt) == 0 || len(key) == 0 {
		return nil, nil, 0, 0, 0, errBadHashFormat
	}
	return salt, key, t, m, p, nil
}

// issueSession writes a signed session cookie valid for ttl.
//
// The cookie carries only an expiry and a nonce; there is one account, so there
// is no identity to encode. Integrity comes from an HMAC keyed by a secret that
// persists in the store, so sessions survive a restart.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, ttl time.Duration) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating session nonce: %w", err)
	}
	payload := fmt.Sprintf("%d.%s", time.Now().Add(ttl).Unix(),
		base64.RawURLEncoding.EncodeToString(nonce))
	value := payload + "." + s.sign(payload)

	secure := r.TLS != nil && !s.insecureCookies
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(ttl),
	})

	// CSRF token: readable by JavaScript, bound to the session by the same key.
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: s.sign("csrf:" + payload), Path: "/",
		HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode,
		Expires: time.Now().Add(ttl),
	})
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil && !s.insecureCookies
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookie, Secure: secure, SameSite: http.SameSiteLaxMode,
		})
	}
}

func (s *Server) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// sessionPayload validates the session cookie and returns its payload.
func (s *Server) sessionPayload(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	idx := strings.LastIndex(c.Value, ".")
	if idx < 0 {
		return "", false
	}
	payload, sig := c.Value[:idx], c.Value[idx+1:]

	if !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return "", false
	}

	expStr, _, ok := strings.Cut(payload, ".")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().After(time.Unix(exp, 0)) {
		return "", false
	}
	return payload, true
}

func (s *Server) authenticated(r *http.Request) bool {
	_, ok := s.sessionPayload(r)
	return ok
}

// checkCSRF validates the double-submit token on state-changing requests.
func (s *Server) checkCSRF(r *http.Request) bool {
	payload, ok := s.sessionPayload(r)
	if !ok {
		return false
	}
	want := s.sign("csrf:" + payload)

	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.FormValue("csrf_token")
	}
	return hmac.Equal([]byte(got), []byte(want))
}
