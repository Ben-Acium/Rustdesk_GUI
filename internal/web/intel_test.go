package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bjones/rustdeskgui/internal/intel"
	"github.com/bjones/rustdeskgui/internal/poller"
	"github.com/bjones/rustdeskgui/internal/store"
)

const testPeerID = "123456789"

// newServerWithDevice stands up a server whose fleet is one known device, so
// the handlers that guard on knownDevice have something to find.
func newServerWithDevice(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	s, h := newTestServer(t)
	s.poller.SetSnapshot(poller.Snapshot{
		Devices: []poller.Device{{ID: testPeerID, IP: "203.0.113.9", Alias: "workshop-pc"}},
	})
	return s, h
}

// do issues an authenticated request, with the CSRF token when one is needed.
func do(t *testing.T, h http.Handler, method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		r.AddCookie(c)
		if c.Name == csrfCookie {
			r.Header.Set("X-CSRF-Token", c.Value)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestIntelEndpointsRequireAuth(t *testing.T) {
	_, h := newServerWithDevice(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/devices/" + testPeerID + "/intel"},
		{http.MethodPut, "/api/devices/" + testPeerID + "/intel"},
		{http.MethodDelete, "/api/devices/" + testPeerID + "/intel"},
		{http.MethodGet, "/api/devices/" + testPeerID + "/probe"},
		{http.MethodPost, "/api/devices/" + testPeerID + "/archive"},
		{http.MethodDelete, "/api/devices/" + testPeerID},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

// Every write here is state-changing and must carry the double-submit token.
func TestIntelWritesRequireCSRF(t *testing.T) {
	_, h := newServerWithDevice(t)
	cookies := login(t, h)

	// Deliberately drop the CSRF cookie, keeping the session.
	var sessionOnly []*http.Cookie
	for _, c := range cookies {
		if c.Name != csrfCookie {
			sessionOnly = append(sessionOnly, c)
		}
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/devices/" + testPeerID + "/intel", `{}`},
		{http.MethodDelete, "/api/devices/" + testPeerID + "/intel", ""},
		{http.MethodPost, "/api/devices/" + testPeerID + "/archive", `{"archived":true}`},
		{http.MethodDelete, "/api/devices/" + testPeerID, ""},
	} {
		rec := do(t, h, c.method, c.path, c.body, sessionOnly)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s without CSRF = %d, want 403", c.method, c.path, rec.Code)
		}
	}
}

func TestIntelRejectsUnknownDevice(t *testing.T) {
	_, h := newServerWithDevice(t)
	cookies := login(t, h)

	rec := do(t, h, http.MethodPut, "/api/devices/999/intel", `{"platform":"Linux"}`, cookies)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// The round trip that matters: the browser posts captured terminal output,
// the server parses it, and the stored report comes back with facts.
func TestIntelCollectionRoundTrip(t *testing.T) {
	_, h := newServerWithDevice(t)
	cookies := login(t, h)

	payload, err := json.Marshal(map[string]any{
		"platform": "Linux",
		"peer": map[string]any{
			"hostname": "workshop-pc", "username": "ben",
			"platform": "Linux", "version": "1.3.2", "terminal_supported": true,
			"displays": []map[string]any{{"name": "DP-1", "width": 2560, "height": 1440, "scale": 1}},
		},
		"output": "user@box:~$ \x1b[1;32mignored\x1b[0m\n" +
			"os.name\tDebian GNU/Linux 12 (bookworm)\n" +
			"cpu.model\tIntel(R) Core(TM) i5-8250U\n" +
			"disk\t/|ext4|103081248|42000000|55000000|44%\n" +
			"disk\t/boot|ext2|500000|90000|380000|20%\n" +
			"net.iface\teth0|00:11:22:33:44:55|up\n",
		"probe": map[string]any{"ran": true, "complete": true, "duration_ms": 1850},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, http.MethodPut, "/api/devices/"+testPeerID+"/intel", string(payload), cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d: %s", rec.Code, rec.Body)
	}

	var got intel.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the stored report: %v", err)
	}
	if got.Platform != intel.PlatformLinux {
		t.Errorf("platform = %q, want linux", got.Platform)
	}
	if v := got.Facts.First("os.name"); v != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("os.name = %q", v)
	}
	if n := len(got.Facts["disk"]); n != 2 {
		t.Errorf("disks = %d, want 2", n)
	}
	if got.Peer.Hostname != "workshop-pc" || got.Peer.Version != "1.3.2" {
		t.Errorf("handshake facts were lost: %+v", got.Peer)
	}
	if len(got.Peer.Displays) != 1 {
		t.Errorf("displays = %d, want 1", len(got.Peer.Displays))
	}
	// The address hbbs recorded is folded in, so the report is self-contained.
	if got.ServerIP != "203.0.113.9" {
		t.Errorf("server_ip = %q", got.ServerIP)
	}
	if got.CollectedAt.IsZero() {
		t.Error("collected_at was not set")
	}

	// And it is readable afterwards.
	rec = do(t, h, http.MethodGet, "/api/devices/"+testPeerID+"/intel", "", cookies)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "bookworm") {
		t.Errorf("GET after PUT = %d: %s", rec.Code, rec.Body)
	}

	// The list's marker reflects it without reading the report.
	rec = do(t, h, http.MethodGet, "/api/devices", "", cookies)
	if !strings.Contains(rec.Body.String(), `"intel":{"`+testPeerID+`"`) {
		t.Errorf("device list does not mark the device as collected: %s", rec.Body)
	}

	rec = do(t, h, http.MethodDelete, "/api/devices/"+testPeerID+"/intel", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/devices/"+testPeerID+"/intel", "", cookies)
	if strings.TrimSpace(rec.Body.String()) != "null" {
		t.Errorf("after delete, GET returned %q, want null", rec.Body.String())
	}
}

// A device is on the other end of this and chooses what it prints. The body
// limit has to hold regardless of what it decides to say.
func TestIntelRejectsOversizedOutput(t *testing.T) {
	_, h := newServerWithDevice(t)
	cookies := login(t, h)

	payload, err := json.Marshal(map[string]any{
		"platform": "Linux",
		"output":   strings.Repeat("junk.key\tvalue\n", 200_000),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, http.MethodPut, "/api/devices/"+testPeerID+"/intel", string(payload), cookies)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an oversized body", rec.Code)
	}
}

func TestProbeEndpointServesAPlatformScript(t *testing.T) {
	_, h := newServerWithDevice(t)
	cookies := login(t, h)

	rec := do(t, h, http.MethodGet, "/api/devices/"+testPeerID+"/probe?platform=Linux", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var p intel.Probe
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Supported || len(p.Lines) == 0 || p.Begin == "" {
		t.Errorf("probe = %+v, want a usable Linux script", p)
	}

	// An unknown platform is answered, not refused: the handshake facts are
	// still worth storing and the collector needs to be told there is no
	// script rather than left to interpret an error.
	rec = do(t, h, http.MethodGet, "/api/devices/"+testPeerID+"/probe?platform=Plan9", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown platform status = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Supported {
		t.Error("an unknown platform should report no script")
	}
}

func TestArchiveHidesAndRestores(t *testing.T) {
	s, h := newServerWithDevice(t)
	cookies := login(t, h)

	rec := do(t, h, http.MethodPost, "/api/devices/"+testPeerID+"/archive", `{"archived":true}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("archive status = %d: %s", rec.Code, rec.Body)
	}
	ids, err := s.store.ArchivedIDs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !ids[testPeerID] {
		t.Error("device was not archived")
	}

	rec = do(t, h, http.MethodPost, "/api/devices/"+testPeerID+"/archive", `{"archived":false}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore status = %d", rec.Code)
	}
	if ids, _ = s.store.ArchivedIDs(t.Context()); ids[testPeerID] {
		t.Error("device was not restored")
	}
}

// Erasing a device must take everything we hold about it, not just the row
// that happens to be most visible.
func TestForgetDeviceErasesEveryRecord(t *testing.T) {
	s, h := newServerWithDevice(t)
	cookies := login(t, h)
	ctx := t.Context()

	if err := s.store.SetMeta(ctx, testPeerID, storeMeta("workshop-pc", "by the lathe")); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetIntel(ctx, testPeerID, timeNow(), []byte(`{"platform":"linux"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetDeviceSecret(ctx, testPeerID, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetArchived(ctx, testPeerID, true); err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, http.MethodDelete, "/api/devices/"+testPeerID, "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d: %s", rec.Code, rec.Body)
	}

	if meta, _ := s.store.AllMeta(ctx); len(meta) != 0 {
		t.Error("the name and note survived")
	}
	if raw, _, _ := s.store.Intel(ctx, testPeerID); raw != nil {
		t.Error("the collected report survived")
	}
	if box, _ := s.store.DeviceSecret(ctx, testPeerID); box != nil {
		t.Error("the saved credential survived")
	}
	if ids, _ := s.store.ArchivedIDs(ctx); len(ids) != 0 {
		t.Error("the archive flag survived")
	}
}

func storeMeta(alias, note string) store.Meta { return store.Meta{Alias: alias, Note: note} }

func timeNow() time.Time { return time.Now().UTC() }
