package web

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

// savedHashLen is the hex length of h1 = SHA256(password||salt).
const savedHashLen = 64

// handleSaveSecret stores a device's login credential.
//
// The body carries h1 as hex, exactly as the client emits it on the
// 'credentials' event. Nothing here ever sees the typed password: the browser
// computes h1 during the handshake and only that leaves the page.
func (s *Server) handleSaveSecret(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	if !s.vault.enabled() {
		writeJSONError(w, http.StatusServiceUnavailable,
			"saved passwords are disabled: no RDGUI_SECRET_KEY is configured")
		return
	}

	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}

	var body struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body")
		return
	}

	// Reject anything that is not an h1. A caller that sent a password by
	// mistake must not have it quietly written to disk.
	hash := strings.ToLower(strings.TrimSpace(body.Hash))
	if len(hash) != savedHashLen {
		writeJSONError(w, http.StatusBadRequest, "credential must be a 64-character hex hash")
		return
	}
	if _, err := hex.DecodeString(hash); err != nil {
		writeJSONError(w, http.StatusBadRequest, "credential must be a 64-character hex hash")
		return
	}

	box, err := s.vault.seal(id, hash)
	if err != nil {
		s.log.Error("sealing device credential failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not save")
		return
	}
	if err := s.store.SetDeviceSecret(r.Context(), id, box); err != nil {
		s.log.Error("saving device credential failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not save")
		return
	}
	s.log.Info("device credential saved", "peer_id", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "saved": true})
}

// handleForgetSecret removes a device's stored credential. Forgetting one that
// was never stored succeeds, so the UI can offer it unconditionally.
func (s *Server) handleForgetSecret(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}
	if err := s.store.DeleteDeviceSecret(r.Context(), id); err != nil {
		s.log.Error("forgetting device credential failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not forget")
		return
	}
	s.log.Info("device credential forgotten", "peer_id", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "saved": false})
}

// savedHashFor unseals a device's credential for the connect pages.
//
// Every failure — no key, no row, a box that will not open — returns the empty
// string. A credential that cannot be used is indistinguishable from one that
// was never saved, and in both cases the page simply asks for a password.
func (s *Server) savedHashFor(r *http.Request, peerID string) string {
	if !s.vault.enabled() || peerID == "" {
		return ""
	}
	box, err := s.store.DeviceSecret(r.Context(), peerID)
	if err != nil {
		s.log.Error("reading device credential failed", "peer_id", peerID, "error", err)
		return ""
	}
	if box == nil {
		return ""
	}
	hash, err := s.vault.open(peerID, box)
	if err != nil {
		// Most likely the key changed. Say so once, clearly, rather than
		// leaving the page to look merely forgetful.
		s.log.Warn("stored device credential could not be opened; "+
			"RDGUI_SECRET_KEY may have changed since it was saved",
			"peer_id", peerID, "error", err)
		return ""
	}
	return hash
}

// savedSecretIDs reports which devices have a credential, for the device list.
// It unseals nothing: the list shows only that one exists.
func (s *Server) savedSecretIDs(r *http.Request) map[string]bool {
	if !s.vault.enabled() {
		return nil
	}
	ids, err := s.store.DeviceSecretIDs(r.Context())
	if err != nil {
		s.log.Error("listing device credentials failed", "error", err)
		return nil
	}
	return ids
}
