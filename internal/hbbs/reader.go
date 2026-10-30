// Package hbbs reads the device inventory out of an OSS RustDesk server's
// SQLite database.
//
// The database belongs to hbbs; this package only ever reads it. Connections
// are opened with query_only(1) so SQLite itself rejects any write, which also
// documents the intent for anyone reading later.
//
// Note that hbbs keeps the database in WAL mode. A WAL reader must be able to
// create the -shm sidecar, so the file's directory has to be writable even
// though we never modify the data. See README for the Docker mount this implies.
package hbbs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	_ "modernc.org/sqlite"
)

// Peer is one row of hbbs's peer table.
//
// The OSS server stores remarkably little: the info column is serialized from a
// struct whose only field is the IP address, so there is no hostname, OS,
// username or client version to read. Anything human-readable has to come from
// this application's own store.
type Peer struct {
	ID string
	// IP is normalized for display: hbbs records IPv4 clients in the
	// IPv4-mapped IPv6 form (::ffff:71.113.27.25), which is noise to read.
	IP        string
	CreatedAt time.Time // first registration, NOT last seen: hbbs never updates it
}

// Reader provides read-only access to db_v2.sqlite3.
type Reader struct {
	db *sql.DB
}

// Open connects to the hbbs database at path.
func Open(path string) (*Reader, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=query_only(1)&_pragma=busy_timeout(5000)", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("hbbs: open %s: %w", path, err)
	}
	// hbbs writes rarely and we only read; a tiny pool avoids holding WAL
	// read locks open any longer than necessary.
	db.SetMaxOpenConns(2)
	db.SetConnMaxIdleTime(time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("hbbs: ping %s: %w", path, err)
	}
	return &Reader{db: db}, nil
}

func (r *Reader) Close() error { return r.db.Close() }

// DeletePeer removes a device from hbbs's peer table. Unlike the read
// connection, this opens a writable connection because it modifies hbbs's data.
//
// Note: hbbs caches peers in memory. If the RustDesk client on the device is
// still running, hbbs will re-register it the next time the client connects.
// Stop or uninstall the client on the device for removal to be permanent.
func DeletePeer(ctx context.Context, path, peerID string) error {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("hbbs: open %s for write: %w", path, err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `delete from peer where id = ?`, peerID); err != nil {
		return fmt.Errorf("hbbs: delete peer %s: %w", peerID, err)
	}
	return nil
}

// peerInfo mirrors the JSON written into peer.info by the OSS server.
type peerInfo struct {
	IP string `json:"ip"`
}

// Peers returns every device that has ever registered with the server.
func (r *Reader) Peers(ctx context.Context) ([]Peer, error) {
	rows, err := r.db.QueryContext(ctx, `select id, created_at, info from peer order by id`)
	if err != nil {
		return nil, fmt.Errorf("hbbs: query peers: %w", err)
	}
	defer rows.Close()

	var out []Peer
	for rows.Next() {
		var (
			id      string
			created sql.NullString
			info    sql.NullString
		)
		if err := rows.Scan(&id, &created, &info); err != nil {
			return nil, fmt.Errorf("hbbs: scan peer: %w", err)
		}

		p := Peer{ID: id}

		// Malformed or absent info must never be fatal: a device we cannot
		// describe is still a device worth listing.
		if info.Valid && info.String != "" {
			var pi peerInfo
			if err := json.Unmarshal([]byte(info.String), &pi); err == nil {
				p.IP = normalizeIP(pi.IP)
			}
		}
		if created.Valid {
			p.CreatedAt = parseSQLiteTime(created.String)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// normalizeIP renders an address the way a person expects to read it.
//
// hbbs accepts clients on a dual-stack socket, so an IPv4 client is stored in
// the IPv4-mapped form ::ffff:71.113.27.25. Real IPv6 addresses are returned in
// canonical form, and anything unparseable is passed through untouched rather
// than discarded.
func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// parseSQLiteTime handles the formats SQLite's current_timestamp default and
// the Go driver may produce. A zero time means "unknown", which callers render
// rather than treating as an error.
func parseSQLiteTime(s string) time.Time {
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.999999999-07:00",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
