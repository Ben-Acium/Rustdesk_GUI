package intel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLocatorDisabledByDefault(t *testing.T) {
	l, err := NewLocator("")
	if err != nil {
		t.Fatal(err)
	}
	if l.Enabled() {
		t.Error("a locator with no URL should be disabled")
	}
	if _, err := l.Lookup(context.Background(), "8.8.8.8"); !errors.Is(err, ErrGeoDisabled) {
		t.Errorf("err = %v, want ErrGeoDisabled", err)
	}
}

func TestLocatorRejectsBadURL(t *testing.T) {
	if _, err := NewLocator("http://example.test/json/"); err == nil {
		t.Error("a URL without {ip} should be refused rather than silently never substituted")
	}
}

// A private address cannot be located and must not be sent to a third party.
func TestLocatorRefusesUnroutableAddressesWithoutAsking(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	l, err := NewLocator(srv.URL + "/{ip}")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.168.1.10", "10.0.0.5", "127.0.0.1", "169.254.3.4"} {
		if _, err := l.Lookup(context.Background(), ip); !errors.Is(err, ErrGeoPrivate) {
			t.Errorf("Lookup(%s) err = %v, want ErrGeoPrivate", ip, err)
		}
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("%d request(s) made for unroutable addresses; want none", n)
	}
}

func TestLocatorParsesAndCaches(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"status":"success","country":"United States",
			"countryCode":"US","regionName":"Virginia","city":"Ashburn","zip":"20149",
			"lat":39.03,"lon":-77.5,"timezone":"America/New_York","isp":"Google LLC",
			"org":"Google Public DNS","as":"AS15169 Google LLC","query":"8.8.8.8"}`))
	}))
	defer srv.Close()

	l, err := NewLocator(srv.URL + "/{ip}")
	if err != nil {
		t.Fatal(err)
	}
	g, err := l.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if g.City != "Ashburn" || g.Region != "Virginia" || g.CountryCode != "US" {
		t.Errorf("parsed geo = %+v", g)
	}
	if g.Lat == 0 || g.Lon == 0 {
		t.Error("coordinates were dropped")
	}
	if g.Source == "" {
		t.Error("a report must say which provider located it")
	}

	if _, err := l.Lookup(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("made %d requests, want 1: the second lookup should be cached", n)
	}
}

// ip-api reports failure as HTTP 200 with a status field, so a naive reader
// would store an empty location as though it were real.
func TestLocatorTreatsStatusFailAsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"fail","message":"reserved range","query":"8.8.8.8"}`))
	}))
	defer srv.Close()

	l, err := NewLocator(srv.URL + "/{ip}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Lookup(context.Background(), "8.8.8.8"); err == nil {
		t.Error("a fail status should be an error, not an empty location")
	}
}
