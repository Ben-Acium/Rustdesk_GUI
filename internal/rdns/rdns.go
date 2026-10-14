// Package rdns resolves device names from IP addresses, since an OSS RustDesk
// server never learns a device's hostname.
//
// The hostname a RustDesk client displays travels in message.proto's PeerInfo,
// inside the peer-to-peer session protocol. hbbs speaks only rendezvous.proto
// and is never told. Reverse DNS is therefore the one automatic source of a
// name, and it is only sometimes useful: a LAN machine resolves to something
// real ("eclipse"), while a consumer ISP returns generated filler
// ("pool-71-113-27-25.rcmdva.east.verizon.net"). IsNoise discards the latter.
package rdns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// Names are cached well beyond the poll interval: a device's PTR record
	// changes far less often than its presence does.
	defaultTTL = time.Hour
	// Negative results are retried sooner, so a device that gains a DNS entry
	// picks it up without a restart.
	negativeTTL = 10 * time.Minute

	lookupTimeout  = 2 * time.Second
	maxConcurrency = 8
)

type entry struct {
	name    string
	expires time.Time
}

// Resolver looks up and caches reverse-DNS names.
// The zero value is not usable; call New.
type Resolver struct {
	resolver *net.Resolver

	mu    sync.Mutex
	cache map[string]entry
}

func New() *Resolver {
	return &Resolver{resolver: net.DefaultResolver, cache: make(map[string]entry)}
}

// Lookup returns a usable hostname for ip, or "" when there is none.
//
// A cached answer is returned immediately; otherwise the lookup runs with a
// short timeout, because a slow resolver must never hold up a presence poll.
func (r *Resolver) Lookup(ctx context.Context, ip string) string {
	if ip == "" {
		return ""
	}
	if name, ok := r.cached(ip); ok {
		return name
	}

	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	name := ""
	names, err := r.resolver.LookupAddr(ctx, ip)
	if err == nil {
		for _, candidate := range names {
			if clean := Clean(candidate, ip); clean != "" {
				name = clean
				break
			}
		}
	}

	ttl := defaultTTL
	if name == "" {
		ttl = negativeTTL
	}
	r.mu.Lock()
	r.cache[ip] = entry{name: name, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
	return name
}

// LookupAll resolves many addresses concurrently, returning a map keyed by IP.
// Addresses that yield no usable name are absent from the result.
func (r *Resolver) LookupAll(ctx context.Context, ips []string) map[string]string {
	out := make(map[string]string, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)

	for _, ip := range ips {
		if ip == "" {
			continue
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if name := r.Lookup(ctx, ip); name != "" {
				mu.Lock()
				out[ip] = name
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return out
}

func (r *Resolver) cached(ip string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[ip]
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.name, true
}

// Clean normalizes a PTR result and rejects it if it carries no information.
// It returns "" for a name that should not be shown.
func Clean(name, ip string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || IsNoise(name, ip) {
		return ""
	}
	return name
}

// IsNoise reports whether a PTR record is generated filler rather than a name
// someone chose.
//
// The reliable signal is that the record embeds the address itself, in any
// punctuation and with or without zero padding:
//
//	71-113-27-25.hsd1.ca.comcast.net
//	pool-71-113-27-25.rcmdva.east.verizon.net
//	071.113.027.025.static.example.net
//
// A name that merely contains digits ("nas-box-2") is kept.
func IsNoise(name, ip string) bool {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	if lower == "" {
		return true
	}

	// Unresolved or malformed reverse zones carry nothing.
	if strings.HasSuffix(lower, ".in-addr.arpa") || strings.HasSuffix(lower, ".ip6.arpa") {
		return true
	}
	if lower == strings.ToLower(ip) {
		return true
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Only the leading labels are examined. A generated record encodes the
	// address there, either packed into one label
	// ("pool-71-113-27-25.rcmdva...") or spread across several
	// ("71.113.27.25.static..."), while the domain beneath it
	// ("east.verizon.net") is shared by genuine names too.
	labels := strings.Split(lower, ".")

	if v4 := parsed.To4(); v4 != nil {
		forms := []string{plainOctets(v4), paddedOctets(v4), plainOctetsReversed(v4)}
		for k := 1; k <= 4 && k <= len(labels); k++ {
			digits := onlyDigits(strings.Join(labels[:k], ""))
			if digits == "" {
				continue
			}
			for _, form := range forms {
				if strings.Contains(digits, form) {
					return true
				}
			}
		}
		return false
	}

	// IPv6: a generated record spells the address out in hex, so the leading
	// labels collapse to the same characters as the expanded address.
	hex := strings.ReplaceAll(strings.ToLower(parsed.String()), ":", "")
	if hex == "" {
		return false
	}
	for k := 1; k <= 8 && k <= len(labels); k++ {
		joined := strings.ReplaceAll(strings.Join(labels[:k], ""), "-", "")
		if strings.Contains(joined, hex) {
			return true
		}
	}
	return false
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func plainOctets(ip net.IP) string {
	var b strings.Builder
	for _, o := range ip {
		b.WriteString(itoa(int(o), false))
	}
	return b.String()
}

func paddedOctets(ip net.IP) string {
	var b strings.Builder
	for _, o := range ip {
		b.WriteString(itoa(int(o), true))
	}
	return b.String()
}

func plainOctetsReversed(ip net.IP) string {
	var b strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		b.WriteString(itoa(int(ip[i]), false))
	}
	return b.String()
}

func itoa(n int, pad bool) string {
	s := ""
	if n == 0 {
		s = "0"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if pad {
		for len(s) < 3 {
			s = "0" + s
		}
	}
	return s
}
