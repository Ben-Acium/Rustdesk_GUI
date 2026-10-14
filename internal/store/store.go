// Package store holds this application's own state: user-supplied device names
// and notes, observed presence, and small secrets.
//
// It is deliberately a separate SQLite database from hbbs's. Nothing this
// application writes should ever land near the RustDesk server's own data.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
create table if not exists device_meta (
	peer_id    text primary key,
	alias      text not null default '',
	note       text not null default '',
	updated_at integer not null
);

-- Current presence, maintained by the poller. Separate from the history table
-- so the common "what is up right now" query touches one row per device.
create table if not exists device_state (
	peer_id     text primary key,
	online      integer not null,
	last_seen   integer,  -- unix seconds; null until first observed online
	last_change integer not null
);

-- Append-only transition log. Only written when a device changes state, so it
-- stays small even with a fast poll interval.
create table if not exists presence_event (
	id      integer primary key autoincrement,
	peer_id text not null,
	online  integer not null,
	at      integer not null
);
create index if not exists idx_presence_peer_at on presence_event(peer_id, at desc);

create table if not exists app_secret (
	key   text primary key,
	value blob not null
);

-- Saved device credentials, one row per device, sealed by internal/web.vault.
-- The plaintext is h1 = SHA256(password||salt): a per-device login credential,
-- the same value the native RustDesk client caches, never the typed password.
-- This table is readable only with the key in RDGUI_SECRET_KEY, which lives
-- outside the data volume; see the README.
create table if not exists device_secret (
	peer_id    text primary key,
	box        blob not null,
	updated_at integer not null
);

-- Collected device inventory: hardware, software, network, location. One row
-- per device, replaced wholesale on each collection.
--
-- The report is stored as JSON rather than columns because its shape is set by
-- what each platform's probe can answer, which differs per OS and changes far
-- more often than this schema should. Readers treat every field as optional.
--
-- Deliberately not sealed like device_secret: this is inventory, not a
-- credential. Sealing it would make it unqueryable and unreadable after a key
-- change, to protect data that is already visible to anyone holding a session
-- on this console.
-- Devices deliberately hidden from the list.
--
-- Not a delete. hbbs's peer table is this application's source of truth and is
-- opened read-only (see internal/hbbs), so a device cannot be removed from the
-- fleet here — only from our view of it. A device stays archived even if it
-- re-registers, until someone restores it.
create table if not exists device_archive (
	peer_id text primary key,
	at      integer not null
);

create table if not exists device_intel (
	peer_id      text primary key,
	collected_at integer not null,
	report       text not null
);
`

type Store struct{ db *sql.DB }

// Meta is the user-supplied description of a device.
type Meta struct {
	Alias string
	Note  string
}

// State is the poller's view of a device.
type State struct {
	Online     bool
	LastSeen   *time.Time
	LastChange time.Time
}

// Open creates or opens the application database at path.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)",
		url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(4)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// AllMeta returns every device's alias and note, keyed by peer ID.
func (s *Store) AllMeta(ctx context.Context) (map[string]Meta, error) {
	rows, err := s.db.QueryContext(ctx, `select peer_id, alias, note from device_meta`)
	if err != nil {
		return nil, fmt.Errorf("store: query meta: %w", err)
	}
	defer rows.Close()

	out := make(map[string]Meta)
	for rows.Next() {
		var id string
		var m Meta
		if err := rows.Scan(&id, &m.Alias, &m.Note); err != nil {
			return nil, fmt.Errorf("store: scan meta: %w", err)
		}
		out[id] = m
	}
	return out, rows.Err()
}

// SetMeta upserts a device's alias and note.
func (s *Store) SetMeta(ctx context.Context, peerID string, m Meta) error {
	_, err := s.db.ExecContext(ctx, `
		insert into device_meta (peer_id, alias, note, updated_at)
		values (?, ?, ?, ?)
		on conflict(peer_id) do update set alias=excluded.alias, note=excluded.note, updated_at=excluded.updated_at`,
		peerID, m.Alias, m.Note, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store: set meta for %s: %w", peerID, err)
	}
	return nil
}

// AllState returns the last known presence of every device the poller has seen.
func (s *Store) AllState(ctx context.Context) (map[string]State, error) {
	rows, err := s.db.QueryContext(ctx, `select peer_id, online, last_seen, last_change from device_state`)
	if err != nil {
		return nil, fmt.Errorf("store: query state: %w", err)
	}
	defer rows.Close()

	out := make(map[string]State)
	for rows.Next() {
		var (
			id         string
			online     int
			lastSeen   sql.NullInt64
			lastChange int64
		)
		if err := rows.Scan(&id, &online, &lastSeen, &lastChange); err != nil {
			return nil, fmt.Errorf("store: scan state: %w", err)
		}
		st := State{Online: online != 0, LastChange: time.Unix(lastChange, 0).UTC()}
		if lastSeen.Valid {
			t := time.Unix(lastSeen.Int64, 0).UTC()
			st.LastSeen = &t
		}
		out[id] = st
	}
	return out, rows.Err()
}

// Observation is one device's presence at a single poll.
type Observation struct {
	PeerID string
	Online bool
}

// RecordPoll applies a full round of observations: it refreshes device_state for
// every device and appends a presence_event only where the state changed. The
// first sighting of a device is recorded only when it is online; see below.
//
// It returns the peer IDs whose state changed, so callers can act on
// transitions without re-reading the table.
func (s *Store) RecordPoll(ctx context.Context, obs []Observation, at time.Time) ([]Observation, error) {
	prev, err := s.AllState(ctx)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()

	ts := at.Unix()
	var changed []Observation

	for _, o := range obs {
		before, known := prev[o.PeerID]
		isChange := !known || before.Online != o.Online

		// A device's first-ever observation only counts as a transition if it
		// is online. Recording "went offline" for a device we had never seen
		// would imply it had been up until that moment, which would both
		// pollute the timeline and inflate its uptime.
		recordEvent := isChange && (known || o.Online)

		// last_seen only advances while the device is actually online.
		var lastSeen *int64
		if o.Online {
			lastSeen = &ts
		} else if before.LastSeen != nil {
			v := before.LastSeen.Unix()
			lastSeen = &v
		}

		lastChange := ts
		if !isChange && known {
			lastChange = before.LastChange.Unix()
		}

		if _, err := tx.ExecContext(ctx, `
			insert into device_state (peer_id, online, last_seen, last_change)
			values (?, ?, ?, ?)
			on conflict(peer_id) do update set
				online=excluded.online, last_seen=excluded.last_seen, last_change=excluded.last_change`,
			o.PeerID, boolToInt(o.Online), lastSeen, lastChange); err != nil {
			return nil, fmt.Errorf("store: upsert state for %s: %w", o.PeerID, err)
		}

		if recordEvent {
			if _, err := tx.ExecContext(ctx,
				`insert into presence_event (peer_id, online, at) values (?, ?, ?)`,
				o.PeerID, boolToInt(o.Online), ts); err != nil {
				return nil, fmt.Errorf("store: insert event for %s: %w", o.PeerID, err)
			}
			changed = append(changed, o)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return changed, nil
}

// Event is a single recorded transition.
type Event struct {
	Online bool
	At     time.Time
}

// History returns a device's transitions newer than since, oldest first.
func (s *Store) History(ctx context.Context, peerID string, since time.Time) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`select online, at from presence_event where peer_id = ? and at >= ? order by at asc`,
		peerID, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: query history: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var online int
		var at int64
		if err := rows.Scan(&online, &at); err != nil {
			return nil, fmt.Errorf("store: scan event: %w", err)
		}
		out = append(out, Event{Online: online != 0, At: time.Unix(at, 0).UTC()})
	}
	return out, rows.Err()
}

// PruneEvents deletes transitions older than the retention window.
func (s *Store) PruneEvents(ctx context.Context, retain time.Duration) (int64, error) {
	res, err := s.db.ExecContext(ctx, `delete from presence_event where at < ?`,
		time.Now().Add(-retain).Unix())
	if err != nil {
		return 0, fmt.Errorf("store: prune events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Secret returns a persistent random secret under key, creating it on first use.
// Used for the session-cookie signing key so sessions survive a restart.
func (s *Store) Secret(ctx context.Context, key string, generate func() ([]byte, error)) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `select value from app_secret where key = ?`, key).Scan(&v)
	switch {
	case err == nil:
		return v, nil
	case err != sql.ErrNoRows:
		return nil, fmt.Errorf("store: read secret %s: %w", key, err)
	}

	v, err = generate()
	if err != nil {
		return nil, fmt.Errorf("store: generate secret %s: %w", key, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`insert into app_secret (key, value) values (?, ?) on conflict(key) do nothing`, key, v); err != nil {
		return nil, fmt.Errorf("store: persist secret %s: %w", key, err)
	}
	// Re-read: a concurrent start may have won the insert.
	if err := s.db.QueryRowContext(ctx, `select value from app_secret where key = ?`, key).Scan(&v); err != nil {
		return nil, fmt.Errorf("store: reread secret %s: %w", key, err)
	}
	return v, nil
}

// SetDeviceSecret stores an already-sealed credential for peerID.
func (s *Store) SetDeviceSecret(ctx context.Context, peerID string, box []byte) error {
	_, err := s.db.ExecContext(ctx, `
		insert into device_secret (peer_id, box, updated_at) values (?, ?, ?)
		on conflict(peer_id) do update set box = excluded.box, updated_at = excluded.updated_at`,
		peerID, box, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store: save device secret: %w", err)
	}
	return nil
}

// DeviceSecret returns the sealed credential for peerID, or nil when none is
// stored. A missing row is not an error: most devices will never have one.
func (s *Store) DeviceSecret(ctx context.Context, peerID string) ([]byte, error) {
	var box []byte
	err := s.db.QueryRowContext(ctx,
		`select box from device_secret where peer_id = ?`, peerID).Scan(&box)
	switch {
	case err == sql.ErrNoRows:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("store: read device secret: %w", err)
	}
	return box, nil
}

// DeleteDeviceSecret forgets peerID's credential. Forgetting one that was never
// stored is not an error, so the caller need not check first.
func (s *Store) DeleteDeviceSecret(ctx context.Context, peerID string) error {
	if _, err := s.db.ExecContext(ctx,
		`delete from device_secret where peer_id = ?`, peerID); err != nil {
		return fmt.Errorf("store: delete device secret: %w", err)
	}
	return nil
}

// DeviceSecretIDs lists the devices that have a credential stored. The device
// list needs only this much — which rows exist — so it never unseals anything.
func (s *Store) DeviceSecretIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `select peer_id from device_secret`)
	if err != nil {
		return nil, fmt.Errorf("store: list device secrets: %w", err)
	}
	defer rows.Close()

	out := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan device secret: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SetArchived hides a device from the list, or restores it.
func (s *Store) SetArchived(ctx context.Context, peerID string, archived bool) error {
	var err error
	if archived {
		_, err = s.db.ExecContext(ctx,
			`insert into device_archive (peer_id, at) values (?, ?)
			 on conflict(peer_id) do update set at = excluded.at`,
			peerID, time.Now().Unix())
	} else {
		_, err = s.db.ExecContext(ctx, `delete from device_archive where peer_id = ?`, peerID)
	}
	if err != nil {
		return fmt.Errorf("store: set archived for %s: %w", peerID, err)
	}
	return nil
}

// ArchivedIDs lists the devices hidden from the list.
func (s *Store) ArchivedIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `select peer_id from device_archive`)
	if err != nil {
		return nil, fmt.Errorf("store: list archived: %w", err)
	}
	defer rows.Close()

	out := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan archived: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ForgetDevice deletes everything this application has recorded about a
// device: its name and note, its presence history, its saved credential and
// its collected inventory.
//
// The device itself is untouched and still registered with hbbs, so it
// reappears in the list as though newly seen. That is the honest outcome:
// this application can forget a device, but it cannot unregister one.
func (s *Store) ForgetDevice(ctx context.Context, peerID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin forget: %w", err)
	}
	defer tx.Rollback()

	for _, q := range []string{
		`delete from device_meta where peer_id = ?`,
		`delete from device_state where peer_id = ?`,
		`delete from presence_event where peer_id = ?`,
		`delete from device_secret where peer_id = ?`,
		`delete from device_intel where peer_id = ?`,
		`delete from device_archive where peer_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, peerID); err != nil {
			return fmt.Errorf("store: forget %s: %w", peerID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit forget: %w", err)
	}
	return nil
}

// SetIntel replaces a device's collected inventory. report is the JSON
// document as the collector produced it; this package does not interpret it.
func (s *Store) SetIntel(ctx context.Context, peerID string, collectedAt time.Time, report []byte) error {
	_, err := s.db.ExecContext(ctx, `
		insert into device_intel (peer_id, collected_at, report) values (?, ?, ?)
		on conflict(peer_id) do update set
			collected_at = excluded.collected_at, report = excluded.report`,
		peerID, collectedAt.Unix(), string(report))
	if err != nil {
		return fmt.Errorf("store: save intel: %w", err)
	}
	return nil
}

// Intel returns a device's stored report and when it was collected. A missing
// row returns nil with a zero time and no error: most devices have never been
// collected.
func (s *Store) Intel(ctx context.Context, peerID string) ([]byte, time.Time, error) {
	var (
		report string
		at     int64
	)
	err := s.db.QueryRowContext(ctx,
		`select report, collected_at from device_intel where peer_id = ?`, peerID).Scan(&report, &at)
	switch {
	case err == sql.ErrNoRows:
		return nil, time.Time{}, nil
	case err != nil:
		return nil, time.Time{}, fmt.Errorf("store: read intel: %w", err)
	}
	return []byte(report), time.Unix(at, 0).UTC(), nil
}

// DeleteIntel discards a device's collected inventory. Discarding one that was
// never collected is not an error.
func (s *Store) DeleteIntel(ctx context.Context, peerID string) error {
	if _, err := s.db.ExecContext(ctx, `delete from device_intel where peer_id = ?`, peerID); err != nil {
		return fmt.Errorf("store: delete intel: %w", err)
	}
	return nil
}

// IntelCollectedAt reports when each device was last collected, for the device
// list. It reads no reports: the list shows only the age.
func (s *Store) IntelCollectedAt(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `select peer_id, collected_at from device_intel`)
	if err != nil {
		return nil, fmt.Errorf("store: list intel: %w", err)
	}
	defer rows.Close()

	out := make(map[string]time.Time)
	for rows.Next() {
		var id string
		var at int64
		if err := rows.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("store: scan intel: %w", err)
		}
		out[id] = time.Unix(at, 0).UTC()
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
