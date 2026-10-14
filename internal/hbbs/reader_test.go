package hbbs

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// newFixtureDB builds a database with hbbs's real peer schema, copied verbatim
// from rustdesk-server/src/database.rs.
func newFixtureDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db_v2.sqlite3")

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		create table if not exists peer (
			guid blob primary key not null,
			id varchar(100) not null,
			uuid blob not null,
			pk blob not null,
			created_at datetime not null default(current_timestamp),
			user blob, status tinyint, note varchar(300),
			info text not null
		) without rowid;
		create unique index if not exists index_peer_id on peer (id);`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	rows := []struct{ guid, id, info, created string }{
		{"g1", "123456789", `{"ip":"10.0.0.14"}`, "2026-01-02 03:04:05"},
		{"g2", "234567890", `{"ip":"10.0.0.22"}`, "2026-02-03 04:05:06"},
		{"g3", "345678901", `not valid json`, "2026-03-04 05:06:07"}, // must not be fatal
		{"g4", "456789012", `{}`, "2026-04-05 06:07:08"},             // info without ip
		{"g5", "567890123", `{"ip":"10.0.0.9"}`, "not-a-timestamp"},  // unparseable date
	}
	for _, r := range rows {
		if _, err := db.Exec(
			`insert into peer (guid, id, uuid, pk, created_at, info) values (?, ?, ?, ?, ?, ?)`,
			[]byte(r.guid), r.id, []byte("uuid"), []byte("pk"), r.created, r.info); err != nil {
			t.Fatalf("insert %s: %v", r.id, err)
		}
	}
	return path
}

func TestPeersParsesInventory(t *testing.T) {
	r, err := Open(newFixtureDB(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	peers, err := r.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	if len(peers) != 5 {
		t.Fatalf("got %d peers, want 5", len(peers))
	}

	byID := make(map[string]Peer, len(peers))
	for _, p := range peers {
		byID[p.ID] = p
	}

	if got := byID["123456789"].IP; got != "10.0.0.14" {
		t.Errorf("IP = %q, want 10.0.0.14", got)
	}
	if got := byID["123456789"].CreatedAt.Format("2006-01-02"); got != "2026-01-02" {
		t.Errorf("CreatedAt = %q, want 2026-01-02", got)
	}

	// Malformed info must leave the IP blank but still list the device: a
	// machine we cannot describe is still a machine.
	if got := byID["345678901"].IP; got != "" {
		t.Errorf("malformed info produced IP %q, want empty", got)
	}
	if got := byID["456789012"].IP; got != "" {
		t.Errorf("info without ip produced %q, want empty", got)
	}

	// An unparseable timestamp yields the zero time, which the UI renders as
	// unknown rather than erroring the whole page.
	if !byID["567890123"].CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want zero time", byID["567890123"].CreatedAt)
	}
}

// The reader must never be able to modify hbbs's database.
func TestReaderIsQueryOnly(t *testing.T) {
	path := newFixtureDB(t)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if _, err := r.db.Exec(`delete from peer`); err == nil {
		t.Fatal("a write succeeded on a query_only connection")
	}
}

func TestOpenMissingFileFails(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope", "db_v2.sqlite3")); err == nil {
		t.Fatal("expected an error opening a nonexistent database")
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		// The form hbbs actually stores for IPv4 clients on a dual-stack socket.
		"::ffff:71.113.27.25": "71.113.27.25",
		"::ffff:10.0.0.14":    "10.0.0.14",
		// Plain IPv4 is already fine.
		"10.0.0.14": "10.0.0.14",
		// Real IPv6 is canonicalized, not mangled into something shorter.
		"2001:db8::1": "2001:db8::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001": "2001:db8::1",
		"::1": "::1",
		// Anything we cannot parse is passed through rather than dropped: a
		// device we cannot describe is still a device.
		"":              "",
		"not-an-ip":     "not-an-ip",
		"10.0.0.14:123": "10.0.0.14:123",
	}
	for in, want := range cases {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// The normalization must apply on the real read path, not just in isolation.
func TestPeersNormalizesMappedAddresses(t *testing.T) {
	path := newFixtureDB(t)

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	if _, err := db.Exec(
		`insert into peer (guid, id, uuid, pk, created_at, info) values (?, ?, ?, ?, ?, ?)`,
		[]byte("g6"), "166378307", []byte("u"), []byte("p"), "2026-10-13 20:08:20",
		`{"ip":"::ffff:71.113.27.25"}`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	peers, err := r.Peers(context.Background())
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}
	for _, p := range peers {
		if p.ID == "166378307" {
			if p.IP != "71.113.27.25" {
				t.Errorf("IP = %q, want 71.113.27.25", p.IP)
			}
			return
		}
	}
	t.Fatal("inserted peer not returned")
}
