package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultGeoURL is ip-api.com's free endpoint.
//
// Two things about it are worth knowing before turning this on:
//
//   - The free tier is HTTP only; HTTPS needs a paid key. The query — one of
//     your devices' public addresses — therefore crosses the network in clear.
//   - It is a third party. Enabling this tells ip-api.com which addresses this
//     console is interested in. Nothing else about the device is sent: not its
//     ID, not its name, not anything the probe collected.
//
// The fields list is explicit rather than defaulted, so what is asked for is
// visible here and the response stays small.
const DefaultGeoURL = "http://ip-api.com/json/{ip}" +
	"?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

// geoTTL is how long a looked-up address is reused. A device's coarse location
// does not change on the timescale of an inventory sweep, and ip-api's free
// tier allows 45 requests a minute, so repeat lookups are pure waste.
const geoTTL = 24 * time.Hour

// maxGeoCache bounds the cache. One entry per address ever collected would
// grow without limit on a fleet behind changing addresses.
const maxGeoCache = 512

// Locator resolves a public IP address to a coarse location.
//
// Disabled unless a URL is configured; Lookup then returns ErrGeoDisabled and
// a report simply carries no location.
type Locator struct {
	url    string
	client *http.Client

	mu    sync.Mutex
	cache map[string]geoEntry
}

type geoEntry struct {
	geo *Geo
	at  time.Time
}

var (
	ErrGeoDisabled = errors.New("intel: location lookup is not configured")
	ErrGeoPrivate  = errors.New("intel: address is not routable on the internet")
)

// NewLocator builds a locator. An empty rawURL disables lookups.
func NewLocator(rawURL string) (*Locator, error) {
	if rawURL == "" {
		return &Locator{}, nil
	}
	if !strings.Contains(rawURL, "{ip}") {
		return nil, fmt.Errorf("intel: geo URL must contain the {ip} placeholder: %q", rawURL)
	}
	if _, err := url.Parse(strings.ReplaceAll(rawURL, "{ip}", "1.1.1.1")); err != nil {
		return nil, fmt.Errorf("intel: geo URL is not a valid URL: %w", err)
	}
	return &Locator{
		url: rawURL,
		// Short: a location is a nice-to-have on a page the user is waiting
		// for, never a reason to make them wait.
		client: &http.Client{Timeout: 6 * time.Second},
		cache:  make(map[string]geoEntry),
	}, nil
}

func (l *Locator) Enabled() bool { return l != nil && l.url != "" }

// Lookup resolves ip. Private, loopback and link-local addresses are refused
// without a request: a third party cannot locate an address that only means
// something on the device's own network, and asking would leak the attempt for
// nothing.
func (l *Locator) Lookup(ctx context.Context, ip string) (*Geo, error) {
	if !l.Enabled() {
		return nil, ErrGeoDisabled
	}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return nil, fmt.Errorf("intel: %q is not an IP address", ip)
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return nil, ErrGeoPrivate
	}
	key := addr.String()

	if g, ok := l.cached(key); ok {
		return g, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.ReplaceAll(l.url, "{ip}", url.PathEscape(key)), nil)
	if err != nil {
		return nil, fmt.Errorf("intel: build geo request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intel: geo lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intel: geo lookup returned %s", resp.Status)
	}

	// Bounded: this is a third-party response being decoded on our side.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return nil, fmt.Errorf("intel: read geo response: %w", err)
	}

	geo, err := parseGeo(body, key, l.url)
	if err != nil {
		return nil, err
	}
	l.store(key, geo)
	return geo, nil
}

// parseGeo reads an ip-api.com response.
//
// Its failure mode is HTTP 200 with {"status":"fail","message":"..."}, so the
// status field is checked before the data is believed.
func parseGeo(body []byte, ip, endpoint string) (*Geo, error) {
	var r struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		Query       string  `json:"query"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("intel: geo response is not JSON: %w", err)
	}
	if r.Status != "" && r.Status != "success" {
		msg := r.Message
		if msg == "" {
			msg = r.Status
		}
		return nil, fmt.Errorf("intel: geo lookup failed: %s", msg)
	}
	if r.Query == "" {
		r.Query = ip
	}
	return &Geo{
		Source:      geoSource(endpoint),
		IP:          r.Query,
		City:        r.City,
		Region:      r.RegionName,
		Country:     r.Country,
		CountryCode: r.CountryCode,
		Zip:         r.Zip,
		Lat:         r.Lat,
		Lon:         r.Lon,
		Timezone:    r.Timezone,
		ISP:         r.ISP,
		Org:         r.Org,
		AS:          r.AS,
	}, nil
}

// geoSource names the provider, so a stored report says where its location
// came from rather than presenting it as something this console knows.
func geoSource(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		return u.Host
	}
	return "geo lookup"
}

func (l *Locator) cached(key string) (*Geo, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.cache[key]
	if !ok || time.Since(e.at) > geoTTL {
		return nil, false
	}
	return e.geo, true
}

func (l *Locator) store(key string, g *Geo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.cache) >= maxGeoCache {
		// Oldest-first would need an ordered structure for a cache this
		// small; dropping everything is simpler and costs one lookup each.
		l.cache = make(map[string]geoEntry)
	}
	l.cache[key] = geoEntry{geo: g, at: time.Now()}
}
