// Package poller keeps an in-memory view of the fleet up to date.
//
// Each round reads the device inventory from hbbs's database, asks the
// rendezvous server which of those devices are online, records any transitions,
// and publishes a snapshot. HTTP handlers read the snapshot and never touch
// either database on the request path.
package poller

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/bjones/rustdeskgui/internal/hbbs"
	"github.com/bjones/rustdeskgui/internal/rdns"
	"github.com/bjones/rustdeskgui/internal/rendezvous"
	"github.com/bjones/rustdeskgui/internal/store"
)

// Device is the joined view of one machine, as the UI shows it.
type Device struct {
	ID    string `json:"id"`
	Alias string `json:"alias"`
	Note  string `json:"note"`
	IP    string `json:"ip"`
	// Hostname is from reverse DNS, empty when none is usable. The OSS server
	// never learns a device's real hostname; see internal/rdns.
	Hostname  string     `json:"hostname"`
	Online    bool       `json:"online"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  *time.Time `json:"last_seen"`
	// Archived devices are ones we have said we no longer care about. They
	// stay in the snapshot — the list hides them behind a toggle rather than
	// dropping them, so restoring one does not require remembering its ID.
	Archived bool `json:"archived"`
}

// Snapshot is one complete poll result.
type Snapshot struct {
	Devices []Device `json:"devices"`
	// Online and Archived both count whole devices, but Online counts only
	// the ones on show: an archived machine coming back up should not change
	// the headline figure for a fleet you are no longer watching.
	Online    int       `json:"online"`
	Archived  int       `json:"archived"`
	UpdatedAt time.Time `json:"updated_at"`
	// Err is the message from the most recent failed poll, empty when healthy.
	// Surfaced in the UI so a silently stale list is impossible.
	Err string `json:"error,omitempty"`
}

type Poller struct {
	hbbs     *hbbs.Reader
	rdv      *rendezvous.Client
	store    *store.Store
	rdns     *rdns.Resolver
	interval time.Duration
	retain   time.Duration
	log      *slog.Logger

	mu   sync.RWMutex
	snap Snapshot
}

type Config struct {
	HBBS   *hbbs.Reader
	Rendez *rendezvous.Client
	Store  *store.Store
	// RDNS resolves hostnames from IPs. Nil disables the lookups entirely.
	RDNS     *rdns.Resolver
	Interval time.Duration
	Retain   time.Duration
	Logger   *slog.Logger
}

func New(c Config) *Poller {
	if c.Interval <= 0 {
		// hbbs considers a peer online for 30s after it registers, so polling
		// faster than that is what keeps the view from lagging reality.
		c.Interval = 20 * time.Second
	}
	if c.Retain <= 0 {
		c.Retain = 90 * 24 * time.Hour
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return &Poller{
		hbbs: c.HBBS, rdv: c.Rendez, store: c.Store, rdns: c.RDNS,
		interval: c.Interval, retain: c.Retain, log: c.Logger,
	}
}

// SetSnapshot publishes a view directly, without polling. Tests use it to
// stand up a known fleet; nothing in the normal path calls it.
func (p *Poller) SetSnapshot(s Snapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.snap = s
}

// Snapshot returns the most recent view. Safe for concurrent use.
func (p *Poller) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.snap
}

// Run polls until ctx is cancelled. It polls once immediately so the UI has
// data as soon as the server accepts connections.
func (p *Poller) Run(ctx context.Context) {
	p.pollLogged(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollLogged(ctx)
		case <-prune.C:
			if n, err := p.store.PruneEvents(ctx, p.retain); err != nil {
				p.log.Warn("pruning presence history failed", "error", err)
			} else if n > 0 {
				p.log.Info("pruned presence history", "rows", n)
			}
		}
	}
}

// pollLogged runs one round, recording any failure in the snapshot so the UI
// can show that the data is stale rather than quietly serving old results.
func (p *Poller) pollLogged(ctx context.Context) {
	if err := p.poll(ctx); err != nil {
		p.log.Warn("poll failed", "error", err)
		p.mu.Lock()
		p.snap.Err = err.Error()
		p.mu.Unlock()
	}
}

// Poll runs a single round. Exported for tests and for the initial sync.
func (p *Poller) Poll(ctx context.Context) error { return p.poll(ctx) }

func (p *Poller) poll(ctx context.Context) error {
	// Both are required. Returning an error rather than dereferencing nil
	// matters because handlers call Poll to refresh after a write, and a
	// misconfigured poller should degrade to a stale list, not a panic.
	if p.hbbs == nil || p.rdv == nil {
		return errors.New("poller: no inventory source is configured")
	}

	peers, err := p.hbbs.Peers(ctx)
	if err != nil {
		return err
	}

	ids := make([]string, len(peers))
	for i, pr := range peers {
		ids[i] = pr.ID
	}

	var states []bool
	if len(ids) > 0 {
		if states, err = p.rdv.Online(ctx, ids); err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	obs := make([]store.Observation, len(ids))
	for i, id := range ids {
		obs[i] = store.Observation{PeerID: id, Online: i < len(states) && states[i]}
	}

	changed, err := p.store.RecordPoll(ctx, obs, now)
	if err != nil {
		return err
	}
	for _, c := range changed {
		p.log.Info("device presence changed", "peer_id", c.PeerID, "online", c.Online)
	}

	meta, err := p.store.AllMeta(ctx)
	if err != nil {
		return err
	}
	state, err := p.store.AllState(ctx)
	if err != nil {
		return err
	}
	archived, err := p.store.ArchivedIDs(ctx)
	if err != nil {
		return err
	}

	// Resolved once per round, concurrently and from cache; a slow resolver
	// must not delay presence.
	var hostnames map[string]string
	if p.rdns != nil {
		ips := make([]string, 0, len(peers))
		for _, pr := range peers {
			if pr.IP != "" {
				ips = append(ips, pr.IP)
			}
		}
		hostnames = p.rdns.LookupAll(ctx, ips)
	}

	devices := make([]Device, 0, len(peers))
	online, hidden := 0, 0
	for _, pr := range peers {
		d := Device{
			ID: pr.ID, IP: pr.IP, FirstSeen: pr.CreatedAt,
			Hostname: hostnames[pr.IP], Archived: archived[pr.ID],
		}
		if m, ok := meta[pr.ID]; ok {
			d.Alias, d.Note = m.Alias, m.Note
		}
		if st, ok := state[pr.ID]; ok {
			d.Online, d.LastSeen = st.Online, st.LastSeen
		}
		if d.Archived {
			hidden++
		} else if d.Online {
			online++
		}
		devices = append(devices, d)
	}

	// Archived last, then online first, then named before unnamed, then by
	// label. Puts the machines you can actually act on at the top.
	sort.SliceStable(devices, func(i, j int) bool {
		a, b := devices[i], devices[j]
		if a.Archived != b.Archived {
			return b.Archived
		}
		if a.Online != b.Online {
			return a.Online
		}
		an, bn := a.Name() != "", b.Name() != ""
		if an != bn {
			return an
		}
		if a.Name() != b.Name() {
			return a.Name() < b.Name()
		}
		return a.ID < b.ID
	})

	p.mu.Lock()
	p.snap = Snapshot{Devices: devices, Online: online, Archived: hidden, UpdatedAt: now}
	p.mu.Unlock()
	return nil
}

// Name is the label to show for a device: the alias you set, else a usable
// reverse-DNS hostname, else empty (callers fall back to the ID).
func (d Device) Name() string {
	if d.Alias != "" {
		return d.Alias
	}
	return d.Hostname
}
