// Command rustdeskgui serves a web UI over a self-hosted OSS RustDesk server.
//
// It reads the device inventory from hbbs's SQLite database, asks the
// rendezvous server which devices are online, and serves the joined view behind
// a password. It never writes to the RustDesk server's data.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Ben-Acium/Rustdesk_GUI/internal/hbbs"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/intel"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/poller"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/rdns"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/rendezvous"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/store"
	"github.com/Ben-Acium/Rustdesk_GUI/internal/web"
)

type config struct {
	listen       string
	hbbsDB       string
	hbbsAddr     string
	dataDir      string
	passwordHash string
	tlsCert      string
	tlsKey       string
	insecureHTTP bool
	rdnsEnabled  bool
	httpListen   string
	publicHost   string
	webClientDir string
	secretKey    string
	geoURL       string
	wsIDAddr     string
	wsRelayAddr  string
	interval     time.Duration
	retain       time.Duration
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if len(os.Args) > 1 && os.Args[1] == "hash" {
		if err := runHash(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		key, err := web.GenerateSecretKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("RDGUI_SECRET_KEY=%s\n", key)
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "resolve" {
		runResolve(os.Args[2:])
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		if err := runHealthcheck(); err != nil {
			fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cfg := loadConfig()
	if err := run(cfg, log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// runHash implements `rustdeskgui hash`, so a plaintext password never has to
// appear in a Compose file or environment.
func runHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	pw := fs.String("password", "", "password to hash (prompts on stdin if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	password := *pw
	if password == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		var line string
		if _, err := fmt.Scanln(&line); err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
		password = line
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	h, err := web.HashPassword(password)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

func loadConfig() config {
	c := config{
		listen:       env("RDGUI_LISTEN", ":8443"),
		hbbsDB:       env("RDGUI_HBBS_DB", "/hbbs-data/db_v2.sqlite3"),
		hbbsAddr:     os.Getenv("RDGUI_HBBS_ADDR"),
		dataDir:      env("RDGUI_DATA_DIR", "/data"),
		passwordHash: os.Getenv("RDGUI_ADMIN_PASSWORD_HASH"),
		tlsCert:      os.Getenv("RDGUI_TLS_CERT"),
		tlsKey:       os.Getenv("RDGUI_TLS_KEY"),
		insecureHTTP: os.Getenv("RDGUI_INSECURE_HTTP") == "1",
		rdnsEnabled:  os.Getenv("RDGUI_RDNS") != "0",
		httpListen:   os.Getenv("RDGUI_HTTP_LISTEN"),
		publicHost:   os.Getenv("RDGUI_PUBLIC_HOST"),
		webClientDir: env("RDGUI_WEBCLIENT_DIR", "/webclient"),
		secretKey:    env("RDGUI_SECRET_KEY", ""),
		// Intel locates a device from the address hbbs recorded for it.
		// Defaulted on because a location is most of the point of collecting
		// one; "off" or an empty value turns it off. See internal/intel/geo.go
		// for exactly what is sent and to whom.
		geoURL:      geoURL(env("RDGUI_GEOIP_URL", intel.DefaultGeoURL)),
		wsIDAddr:    env("RDGUI_HBBS_WS", "127.0.0.1:21118"),
		wsRelayAddr: env("RDGUI_HBBR_WS", "127.0.0.1:21119"),
		interval:    envDuration("RDGUI_POLL_INTERVAL", 20*time.Second),
		retain:      envDuration("RDGUI_RETAIN", 90*24*time.Hour),
	}

	flag.StringVar(&c.listen, "listen", c.listen, "address to listen on")
	flag.StringVar(&c.hbbsDB, "hbbs-db", c.hbbsDB, "path to hbbs db_v2.sqlite3")
	flag.StringVar(&c.hbbsAddr, "hbbs-addr", c.hbbsAddr,
		"hbbs NAT port as host:port (the rendezvous port minus one); must not be loopback")
	flag.StringVar(&c.dataDir, "data-dir", c.dataDir, "directory for this application's own state")
	flag.DurationVar(&c.interval, "interval", c.interval, "presence poll interval")
	flag.Parse()
	return c
}

func run(cfg config, log *slog.Logger) error {
	if cfg.passwordHash == "" {
		return errors.New("RDGUI_ADMIN_PASSWORD_HASH is not set; generate one with `rustdeskgui hash`")
	}

	// A loopback rendezvous address can never return presence, and the symptom
	// (a bare EOF every poll) is obscure. Refuse it at startup instead.
	if cfg.hbbsAddr == "" {
		return fmt.Errorf("RDGUI_HBBS_ADDR is not set; it must be the host's routable "+
			"address on hbbs's NAT port, not loopback%s", suggestAddr())
	}
	if err := rendezvous.ValidateAddr(cfg.hbbsAddr); err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.dataDir, 0o750); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	hbbsDB, err := hbbs.Open(cfg.hbbsDB)
	if err != nil {
		return err
	}
	defer hbbsDB.Close()

	st, err := store.Open(filepath.Join(cfg.dataDir, "rustdeskgui.sqlite3"))
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	secret, err := st.Secret(ctx, "session_hmac", func() ([]byte, error) {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		return b, err
	})
	if err != nil {
		return err
	}

	var resolver *rdns.Resolver
	if cfg.rdnsEnabled {
		resolver = rdns.New()
	} else {
		log.Info("reverse DNS lookups disabled; devices show their alias or ID only")
	}

	p := poller.New(poller.Config{
		HBBS:     hbbsDB,
		RDNS:     resolver,
		Rendez:   &rendezvous.Client{Addr: cfg.hbbsAddr, Timeout: 10 * time.Second},
		Store:    st,
		Interval: cfg.interval,
		Retain:   cfg.retain,
		Logger:   log,
	})
	go p.Run(ctx)

	wc := web.WebClientConfig{
		Dir:         cfg.webClientDir,
		IDAddr:      cfg.wsIDAddr,
		RelayAddr:   cfg.wsRelayAddr,
		ServerKey:   readServerKey(cfg.hbbsDB, log),
		MyID:        webClientID(secret),
		PreferCodec: env("RDGUI_PREFER_CODEC", "vp8"),
	}
	if wc.Enabled() {
		log.Info("browser client enabled", "hbbs_ws", wc.IDAddr, "hbbr_ws", wc.RelayAddr)
	} else {
		log.Warn("browser client disabled: bundle or hbbs public key missing",
			"dir", cfg.webClientDir)
	}

	if cfg.geoURL == "" {
		log.Info("device location lookups are disabled")
	} else {
		log.Info("device location lookups are enabled; "+
			"collecting a device sends its public IP to this endpoint",
			"endpoint", geoHost(cfg.geoURL))
	}

	if cfg.secretKey == "" {
		log.Info("saved device passwords are disabled; set RDGUI_SECRET_KEY " +
			"(generate one with `rustdeskgui genkey`) to enable them")
	} else {
		log.Info("saved device passwords are enabled")
	}

	srv, err := web.New(web.Config{
		Poller: p, Store: st, PasswordHash: cfg.passwordHash, Secret: secret, Logger: log,
		WebClient:       wc,
		SecretKey:       cfg.secretKey,
		GeoURL:          cfg.geoURL,
		InsecureCookies: cfg.httpListen != "",
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// HTTP/2 is deliberately disabled. It has no Upgrade mechanism, so a
		// WebSocket handshake arriving over h2 loses its Connection and
		// Upgrade headers and the rendezvous proxy forwards a plain GET that
		// hbbs closes on. Browsers fall back to HTTP/1.1 for WebSockets
		// anyway, and nothing here benefits from multiplexing.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	errCh := make(chan error, 2)
	go func() { errCh <- serve(httpSrv, cfg, log) }()

	// A second, plaintext listener exists for one reason: a page served over
	// HTTPS may not open a ws:// socket, and hbbs/hbbr speak plain WebSocket.
	// Until 21118/21119 are fronted by TLS, the browser client has to be
	// delivered over HTTP too.
	var plainSrv *http.Server
	if cfg.httpListen != "" {
		plainSrv = &http.Server{
			Addr:              cfg.httpListen,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Warn("serving plaintext HTTP for the browser client; the page can be "+
			"tampered with in transit, so use it only on a trusted network",
			"addr", cfg.httpListen)
		go func() { errCh <- plainSrv.ListenAndServe() }()
	}

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if plainSrv != nil {
		_ = plainSrv.Shutdown(shutdownCtx)
	}
	return httpSrv.Shutdown(shutdownCtx)
}

// serve starts the listener, choosing TLS unless explicitly told otherwise.
// Port 8443 implies HTTPS, so a missing certificate generates a self-signed one
// rather than silently downgrading to plaintext.
func serve(httpSrv *http.Server, cfg config, log *slog.Logger) error {
	if cfg.insecureHTTP {
		log.Warn("serving plaintext HTTP because RDGUI_INSECURE_HTTP=1; only safe behind a TLS-terminating proxy",
			"addr", cfg.listen)
		return httpSrv.ListenAndServe()
	}

	certFile, keyFile := cfg.tlsCert, cfg.tlsKey
	if certFile == "" || keyFile == "" {
		certFile = filepath.Join(cfg.dataDir, "self-signed.crt")
		keyFile = filepath.Join(cfg.dataDir, "self-signed.key")
		// The certificate must name the address the browser actually types, or
		// it cannot be accepted for the WebSocket riding the same origin.
		if err := ensureSelfSigned(certFile, keyFile, cfg.publicHost); err != nil {
			return err
		}
		log.Warn("using a self-signed certificate; your browser will warn on first visit",
			"cert", certFile,
			"hint", "set RDGUI_TLS_CERT and RDGUI_TLS_KEY to use a real certificate")
	}

	httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	log.Info("listening", "addr", cfg.listen, "tls", true)
	return httpSrv.ListenAndServeTLS(certFile, keyFile)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	// Bare numbers are read as seconds, which is the likelier intent in a
	// Compose file than a parse failure at startup.
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	return def
}

// runHealthcheck backs the container HEALTHCHECK. The distroless image has no
// shell and no curl, so the binary probes itself.
//
// The certificate is skipped deliberately: by default it is the self-signed one
// this process generated, and the check is a liveness probe over loopback, not
// an authentication boundary.
func runHealthcheck() error {
	addr := env("RDGUI_LISTEN", ":8443")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}

	scheme := "https"
	if os.Getenv("RDGUI_INSECURE_HTTP") == "1" {
		scheme = "http"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback liveness probe
		},
	}

	resp, err := client.Get(scheme + "://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// suggestAddr turns the "not set" error into something actionable by naming the
// address this host would most likely use.
func suggestAddr() string {
	ip := rendezvous.OutboundIP()
	if ip == "" {
		return ""
	}
	return fmt.Sprintf(" (try %s:21115)", ip)
}

// runResolve implements `rustdeskgui resolve <ip>...`, which answers the
// question "why is this device showing as a bare ID?" from inside the
// container, where there is no shell to run dig with.
func runResolve(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: rustdeskgui resolve <ip>...")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for _, ip := range args {
		names, err := net.DefaultResolver.LookupAddr(ctx, ip)
		switch {
		case err != nil:
			fmt.Printf("%-18s no PTR record (%v)\n", ip, err)
			continue
		case len(names) == 0:
			fmt.Printf("%-18s no PTR record\n", ip)
			continue
		}

		for _, raw := range names {
			name := strings.TrimSuffix(raw, ".")
			if rdns.IsNoise(raw, ip) {
				fmt.Printf("%-18s %-45s rejected: generated from the IP\n", ip, name)
				continue
			}
			fmt.Printf("%-18s %-45s used as the device name\n", ip, name)
		}
	}
}

// readServerKey loads hbbs's base64 public key, which sits next to its database.
// A punch-hole request whose licence_key does not match is refused with
// LICENSE_MISMATCH, so the browser client cannot work without it.
func readServerKey(hbbsDB string, log *slog.Logger) string {
	if v := os.Getenv("RDGUI_SERVER_KEY"); v != "" {
		return strings.TrimSpace(v)
	}
	path := filepath.Join(filepath.Dir(hbbsDB), "id_ed25519.pub")
	b, err := os.ReadFile(path)
	if err != nil {
		log.Warn("could not read hbbs public key; the browser client stays disabled",
			"path", path, "error", err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

// webClientID derives a stable identifier for this console, so the controlled
// device sees the same peer across restarts rather than a new one each time.
func webClientID(secret []byte) string {
	sum := sha256.Sum256(append([]byte("rustdeskgui-web-client"), secret...))
	n := binary.BigEndian.Uint64(sum[:8]) % 900000000
	return strconv.FormatUint(n+100000000, 10)
}

// geoURL normalises the location-lookup setting. "off", "0" and "none" are
// accepted alongside an empty value so that turning the feature off does not
// require knowing that empty is the magic word.
func geoURL(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "off", "0", "no", "none", "false", "disabled":
		return ""
	}
	return strings.TrimSpace(v)
}

// geoHost names the provider for the startup log, without the query string
// that would otherwise fill a log line with field selectors.
func geoHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}
