package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Ben-Acium/Rustdesk_GUI/internal/hbbs"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/intel"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/poller"
)

// maxReportBytes bounds a stored report. The probe output is already capped
// before parsing; this is the backstop on the document as a whole.
const maxReportBytes = 512 << 10

// handleDevicePage serves one device's detail view.
func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dev, ok := s.device(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	csrf := ""
	if payload, ok := s.sessionPayload(r); ok {
		csrf = s.sign("csrf:" + payload)
	}

	// The page hosts a real session worker when Intel runs, so it needs the
	// client's policy rather than the site-wide one.
	if s.webClient.Enabled() {
		w.Header().Set("Content-Security-Policy", s.webClient.csp())
	}
	s.render(w, "device.html", map[string]any{
		"Device":       dev,
		"Name":         displayName(dev),
		"CSRF":         csrf,
		"WebClient":    s.webClient.Enabled(),
		"SavedHash":    s.savedHashFor(r, id),
		"CanSave":      s.vault.enabled(),
		"CanLocate":    s.locator.Enabled(),
		"CanRemovePeer": s.hbbsDBPath != "",
	})
}

// handleProbe hands the collector the script for a device's platform.
//
// The platform comes from the caller because only the browser knows it: it is
// in the handshake's PeerInfo, which this process never sees. Fresh markers
// are generated per request; see intel.NewProbe.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	if !s.knownDevice(r.PathValue("id")) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}
	probe, err := intel.NewProbe(r.URL.Query().Get("platform"))
	if err != nil {
		s.log.Error("building probe failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not build a probe")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, probe)
}

// handleGetIntel returns a device's stored report, or null when none exists.
func (s *Server) handleGetIntel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}
	raw, _, err := s.store.Intel(r.Context(), id)
	if err != nil {
		s.log.Error("reading intel failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not read")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if raw == nil {
		_, _ = w.Write([]byte("null\n"))
		return
	}
	_, _ = w.Write(raw)
}

// handlePutIntel accepts one collection from the browser.
//
// The browser is transport only: it connects, takes the handshake facts and
// captures whatever the probe printed between the markers. Everything that
// needs judgement — parsing that capture, bounding it, deciding what counts as
// a fact — happens here, where it can be tested and where a device cannot
// choose the code path by what it emits.
func (s *Server) handlePutIntel(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	id := r.PathValue("id")
	dev, ok := s.device(id)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}

	var body struct {
		Platform string            `json:"platform"`
		Peer     intel.Peer        `json:"peer"`
		Output   string            `json:"output"`
		Probe    intel.ProbeResult `json:"probe"`
		// Tail is raw terminal output, kept only when the probe failed so the
		// page can show what the shell was doing. Cleaned before storing.
		Tail string `json:"tail"`
	}
	limit := int64(intel.MaxOutputLen + 32<<10)
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed or oversized body")
		return
	}

	if !body.Probe.Complete && body.Tail != "" {
		body.Probe.Tail = intel.CleanTail(body.Tail)
	}

	report := intel.Report{
		CollectedAt: time.Now().UTC(),
		Platform:    intel.NormalizePlatform(body.Platform),
		Peer:        body.Peer,
		Facts:       intel.ParseOutput(body.Output),
		Probe:       body.Probe,
		ServerIP:    dev.IP,
	}
	report.Geo = s.locate(r.Context(), dev.IP)

	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > maxReportBytes {
		s.log.Error("encoding intel failed", "peer_id", id, "error", err, "bytes", len(encoded))
		writeJSONError(w, http.StatusBadRequest, "report is too large to store")
		return
	}
	if err := s.store.SetIntel(r.Context(), id, report.CollectedAt, encoded); err != nil {
		s.log.Error("saving intel failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not save")
		return
	}

	s.log.Info("device intel collected", "peer_id", id,
		"platform", report.Platform, "facts", len(report.Facts),
		"probe_ran", report.Probe.Ran, "probe_complete", report.Probe.Complete)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)
}

// locate resolves a device's address, best effort. A location is an extra on
// a report, never a reason to fail one, so every error here is logged at debug
// and swallowed.
func (s *Server) locate(ctx context.Context, ip string) *intel.Geo {
	if !s.locator.Enabled() || ip == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	geo, err := s.locator.Lookup(ctx, ip)
	switch {
	case err == nil:
		return geo
	case errors.Is(err, intel.ErrGeoPrivate):
		// A device behind NAT whose recorded address is its LAN one. Normal.
		s.log.Debug("no location for a private address", "ip", ip)
	default:
		s.log.Warn("location lookup failed", "ip", ip, "error", err)
	}
	return nil
}

func (s *Server) handleDeleteIntel(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}
	if err := s.store.DeleteIntel(r.Context(), id); err != nil {
		s.log.Error("deleting intel failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not delete")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleArchive hides a device from the list, or restores it.
func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request) {
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
		Archived bool `json:"archived"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	if err := s.store.SetArchived(r.Context(), id, body.Archived); err != nil {
		s.log.Error("archiving device failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not save")
		return
	}
	// Refresh so the list reflects the change on the next read rather than at
	// the next poll.
	if err := s.poller.Poll(r.Context()); err != nil {
		s.log.Warn("refresh after archive failed", "error", err)
	}
	s.log.Info("device archive state changed", "peer_id", id, "archived", body.Archived)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "archived": body.Archived})
}

// handleForgetDevice discards everything this console has recorded about a
// device.
//
// It does not remove the device from the RustDesk server. hbbs's peer table is
// the source of truth and is opened read-only by design, so a forgotten device
// reappears in the list the moment the next poll reads that table — just
// without its name, note, history, saved password or inventory. Archiving is
// what hides a device for good; this is what erases what we know about it.
func (s *Server) handleForgetDevice(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}
	if err := s.store.ForgetDevice(r.Context(), id); err != nil {
		s.log.Error("forgetting device failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not forget")
		return
	}
	if err := s.poller.Poll(r.Context()); err != nil {
		s.log.Warn("refresh after forget failed", "error", err)
	}
	s.log.Info("device record erased", "peer_id", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRemovePeer deletes the device from hbbs's peer table and erases all
// console records for it. Because hbbs caches peers in memory, the device will
// re-register if the RustDesk client is still running on it; stop or uninstall
// the client there for removal to stick.
func (s *Server) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	if s.hbbsDBPath == "" {
		writeJSONError(w, http.StatusNotFound, "peer removal is not configured")
		return
	}
	id := r.PathValue("id")
	if !s.knownDevice(id) {
		writeJSONError(w, http.StatusNotFound, "unknown device")
		return
	}
	if err := hbbs.DeletePeer(r.Context(), s.hbbsDBPath, id); err != nil {
		s.log.Error("removing peer from hbbs failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "could not remove peer from server")
		return
	}
	if err := s.store.ForgetDevice(r.Context(), id); err != nil {
		s.log.Error("forgetting device after peer removal failed", "peer_id", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "peer removed from server but console records remain")
		return
	}
	if err := s.poller.Poll(r.Context()); err != nil {
		s.log.Warn("refresh after peer removal failed", "error", err)
	}
	s.log.Info("device removed from hbbs and console records erased", "peer_id", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// device returns one device from the current snapshot.
func (s *Server) device(id string) (poller.Device, bool) {
	for _, d := range s.poller.Snapshot().Devices {
		if d.ID == id {
			return d, true
		}
	}
	return poller.Device{}, false
}
