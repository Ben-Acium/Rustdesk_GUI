package web

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// newWSProxy proxies a WebSocket upgrade to one of hbbs/hbbr.
//
// Routing the sockets through this origin rather than letting the browser dial
// 21118/21119 directly buys three things:
//
//   - One TLS certificate. A page on https:// may not open ws://, so direct
//     connections would need TLS on both WebSocket ports, and a browser will
//     not prompt to accept a certificate for a WebSocket - it just fails. As
//     same-origin paths they inherit the exception the page already has.
//   - 21118/21119 no longer need to be reachable from the internet.
//   - Correct client addresses. hbbs/hbbr trust X-Real-IP, so anything able to
//     reach them directly can forge one. Here the header is overwritten with
//     the peer address actually observed, and any value the client supplied is
//     discarded.
//
// httputil.ReverseProxy handles 101 responses and hands the hijacked
// connection over, so no bespoke splicing is needed.
func newWSProxy(target string, log *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL = &url.URL{Scheme: "http", Host: target, Path: "/"}
			r.Out.Host = target

			// Never relay a client-supplied forwarding header: hbbs believes it.
			r.Out.Header.Del("X-Forwarded-For")
			r.Out.Header.Del("X-Forwarded-Host")
			r.Out.Header.Del("X-Forwarded-Proto")
			r.Out.Header.Del("X-Real-IP")

			// Our session cookie is for this service alone; hbbs has no use
			// for it and should not be handed credentials.
			r.Out.Header.Del("Cookie")

			if host, _, err := net.SplitHostPort(r.In.RemoteAddr); err == nil {
				r.Out.Header.Set("X-Real-IP", host)
				r.Out.Header.Set("X-Forwarded-For", host)
			}
		},
		// A relayed desktop session is long-lived and mostly idle in one
		// direction; the default transport timeouts would cut it.
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			IdleConnTimeout:     0,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("websocket proxy failed", "target", target, "path", r.URL.Path, "error", err)
			http.Error(w, "upstream rendezvous server unavailable", http.StatusBadGateway)
		},
	}
}

// wsOrigin returns the scheme and authority the browser should use to reach
// this server, derived from the request so it is correct on either listener.
func wsOrigin(r *http.Request) string {
	scheme := "ws"
	if r.TLS != nil {
		scheme = "wss"
	}
	return scheme + "://" + r.Host
}
