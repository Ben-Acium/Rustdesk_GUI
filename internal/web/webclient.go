package web

import (
	_ "embed"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// WebClientConfig describes the browser-based RustDesk client served at /client.
//
// The bundle is CortenDesk's from-scratch TypeScript implementation of the
// RustDesk protocol (AGPL-3.0), built into static assets at image build time.
// Its documented contract is a global:
//
//	window.__RD__ = { peerId?, serverKeyB64, wsIdUrl, wsRelayUrl, myId, myName }
//
// The peer id is left out deliberately: the client reads ?id= from the URL
// itself, which keeps the injected config identical for every device.
type WebClientConfig struct {
	// Dir holds the built bundle (app.js, app.css, session.worker.js).
	Dir string
	// IDAddr and RelayAddr are hbbs's and hbbr's WebSocket listeners as seen
	// from this process. The browser never contacts them directly; it speaks to
	// same-origin paths that proxy here. See newWSProxy for why.
	IDAddr, RelayAddr string
	// ServerKey is hbbs's base64 public key, from id_ed25519.pub. hbbs refuses
	// a punch-hole request with LICENSE_MISMATCH when it does not match.
	ServerKey string
	// MyID identifies this client to the device being controlled.
	MyID string
	// PreferCodec seeds the client's saved codec preference on first visit.
	//
	// Left to decide for itself, the client advertises every codec Chrome
	// claims to decode and the device picks the best one it can encode, which
	// in practice is AV1. Chrome accepts an AV1 decoder configuration readily
	// but does not reliably render RustDesk's stream, giving a black screen
	// while input and clipboard carry on working.
	//
	// The default is VP8 because that is what has actually been observed to
	// render. VP9 looked like the better pick on paper - broader hardware
	// support, better compression - but it was never confirmed end to end, and
	// a default exists to work on first try rather than to be optimal. VP9 and
	// AV1 are both worth trying from the session's display menu, where any
	// choice is remembered and takes precedence over this.
	//
	// Empty disables the seeding entirely.
	PreferCodec string
}

// codecNames mirrors the client's own CODECS list; anything else is ignored by
// its validator, so refuse it here rather than write a value it will discard.
var codecNames = map[string]bool{
	"auto": true, "vp9": true, "h264": true, "h265": true, "vp8": true, "av1": true,
}

// Enabled reports whether every prerequisite for serving the client is present.
// A missing bundle or key disables the feature rather than failing startup,
// since the device list is useful on its own.
func (c WebClientConfig) Enabled() bool {
	if c.Dir == "" || c.ServerKey == "" || c.IDAddr == "" || c.RelayAddr == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(c.Dir, "app.js"))
	return err == nil && !st.IsDir()
}

// PageURL links to a device in the browser client. The page and its WebSocket
// share this origin, so it is relative.
func (c WebClientConfig) PageURL(peerID string) string {
	return "/client?id=" + url.QueryEscape(peerID)
}

// csp relaxes the site-wide policy for this one page.
//
// The bundle inlines its WASM as base64 and instantiates it at runtime, which
// needs 'wasm-unsafe-eval', and the decoder runs in a worker that paints
// through blob URLs. The WebSocket is same-origin, so 'self' covers
// connect-src and no host has to be named.
func (c WebClientConfig) csp() string {
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' 'wasm-unsafe-eval' blob:",
		"worker-src 'self' blob:",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:",
		"media-src 'self' blob:",
		"connect-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; ")
}

// handleClient serves the page that hosts the browser client.
func (s *Server) handleClient(w http.ResponseWriter, r *http.Request) {
	if !s.webClient.Enabled() {
		http.Error(w, "the browser client is not configured on this server", http.StatusNotFound)
		return
	}

	id := r.URL.Query().Get("id")
	name := id
	for _, d := range s.poller.Snapshot().Devices {
		if d.ID == id {
			if n := d.Name(); n != "" {
				name = n
			}
			break
		}
	}

	w.Header().Set("Content-Security-Policy", s.webClient.csp())
	s.render(w, "client.html", map[string]any{
		"PeerID":   id,
		"PeerName": name,
		"Insecure": r.TLS == nil,
		// Rendered into the page rather than fetched, because the bundle
		// decides whether to sign straight in while it initialises — an
		// asynchronous fetch would lose that race every time.
		"SavedHash": s.savedHashFor(r, id),
		"CanSave":   s.vault.enabled(),
	})
}

// handleStandalone serves the files-only and terminal-only pages.
//
// Both use ConnType values that negotiate no video, so the remote desktop is
// never requested at all. See webclient-ext/rdgui-standalone.ts for why the
// upstream UI cannot reach these without a desktop session first.
func (s *Server) handleStandalone(mode string) http.HandlerFunc {
	title, blurb := "Files", "Browse and transfer files over a dedicated file-transfer connection."
	if mode == "terminal" {
		title, blurb = "Terminal", "Open a shell over a dedicated terminal connection."
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if !s.webClient.Enabled() {
			http.Error(w, "the browser client is not configured on this server", http.StatusNotFound)
			return
		}

		id := r.URL.Query().Get("id")
		name := id
		for _, d := range s.poller.Snapshot().Devices {
			if d.ID == id {
				if n := d.Name(); n != "" {
					name = n
				}
				break
			}
		}

		w.Header().Set("Content-Security-Policy", s.webClient.csp())
		s.render(w, "standalone.html", map[string]any{
			"Title":     title,
			"PeerID":    id,
			"PeerName":  name,
			"Blurb":     blurb,
			"SavedHash": s.savedHashFor(r, id),
			"CanSave":   s.vault.enabled(),
		})
	}
}

// handleClientConfig serves window.__RD__ as a script rather than inlining it,
// so the page needs no 'unsafe-inline' in script-src.
//
// The socket URLs are derived from the request, so the same handler is correct
// whether the page arrived over TLS (wss://) or not (ws://).
func (s *Server) handleClientConfig(w http.ResponseWriter, r *http.Request) {
	if !s.webClient.Enabled() {
		http.Error(w, "// browser client not configured", http.StatusNotFound)
		return
	}

	origin := wsOrigin(r)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `// generated by rustdeskgui
window.__RD__ = {
  serverKeyB64: %q,
  wsIdUrl: %q,
  wsRelayUrl: %q,
  myId: %q,
  myName: %q,
  workerUrl: "/rdclient/session.worker.js"
};
`, s.webClient.ServerKey, origin+"/ws/id", origin+"/ws/relay", s.webClient.MyID, "rustdeskgui")

	// Seed the client's saved preferences, but only when it has none: a choice
	// made in its own menus must never be overwritten from here. The client
	// validates every field against its defaults, so a partial object is safe
	// and an unknown key is simply ignored.
	if codecNames[s.webClient.PreferCodec] {
		fmt.Fprintf(w, `
try {
  var k = "cortendesk.rdprefs.v1";
  if (window.localStorage && localStorage.getItem(k) === null) {
    localStorage.setItem(k, JSON.stringify({ codec: %q }));
  }
} catch (e) { /* private window or blocked storage: the codec menu still works */ }
`, s.webClient.PreferCodec)
	}
}

//go:embed static/logo.svg
var logoSVG []byte

// handleClientLogo answers the bundle's /rdclient/logo.png.
//
// That path is a Laravel public asset in the upstream project and is not part
// of the esbuild output, so without this the top bar logs a 404 on every load.
// An SVG is served under the .png name deliberately: browsers honour the
// Content-Type, and it keeps a binary blob out of the repository.
//
// It is our own mark, not the upstream one, so the bundle's two <img> tags
// need no further treatment — only the wordmarks beside them are relabelled,
// in static/rdclient-overrides.css.
func (s *Server) handleClientLogo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(logoSVG)
}

// handleClientAssets serves the built bundle from disk.
//
// It is not embedded: the bundle is produced by a separate AGPL-3.0 project at
// image build time, so it stays its own file tree rather than being compiled
// into this binary.
func (s *Server) handleClientAssets() http.Handler {
	return http.StripPrefix("/rdclient/", http.FileServer(http.Dir(s.webClient.Dir)))
}
