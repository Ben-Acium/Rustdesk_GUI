package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A device's first observation is a transition (we knew nothing before), and a
// repeat of the same state must not append another event.
func TestRecordPollWritesEventsOnlyOnTransition(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	t0 := time.Now().Add(-10 * time.Minute).Truncate(time.Second)

	changed, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: true}}, t0)
	if err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if len(changed) != 1 {
		t.Fatalf("first observation reported %d changes, want 1", len(changed))
	}

	// Same state again: no new event.
	changed, err = s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: true}}, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("unchanged observation reported %d changes, want 0", len(changed))
	}

	// Going offline is a transition.
	changed, err = s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: false}}, t0.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if len(changed) != 1 || changed[0].Online {
		t.Errorf("offline transition = %+v, want one offline change", changed)
	}

	events, err := s.History(ctx, "a", t0.Add(-time.Hour))
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("recorded %d events, want 2", len(events))
	}
	if !events[0].Online || events[1].Online {
		t.Errorf("events = %+v, want online then offline", events)
	}
}

// last_seen must mark the last time the device was actually up, and must not
// drift forward while it is offline.
func TestLastSeenOnlyAdvancesWhileOnline(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	online := time.Now().Add(-time.Hour).Truncate(time.Second)
	if _, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: true}}, online); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}

	later := online.Add(30 * time.Minute)
	if _, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: false}}, later); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if _, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: false}}, later.Add(time.Hour)); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}

	state, err := s.AllState(ctx)
	if err != nil {
		t.Fatalf("AllState: %v", err)
	}
	st := state["a"]
	if st.Online {
		t.Error("device reported online after going offline")
	}
	if st.LastSeen == nil || !st.LastSeen.Equal(online.UTC()) {
		t.Errorf("last seen = %v, want %v", st.LastSeen, online.UTC())
	}
}

// A device never observed online has no last-seen time at all, which the UI
// renders differently from "offline for a long while".
func TestNeverOnlineHasNoLastSeen(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: false}}, time.Now()); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	state, _ := s.AllState(ctx)
	if state["a"].LastSeen != nil {
		t.Errorf("last seen = %v, want nil", state["a"].LastSeen)
	}
}

func TestSetMetaUpserts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.SetMeta(ctx, "a", Meta{Alias: "workshop", Note: "upstairs"}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := s.SetMeta(ctx, "a", Meta{Alias: "workshop-pc", Note: ""}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	meta, err := s.AllMeta(ctx)
	if err != nil {
		t.Fatalf("AllMeta: %v", err)
	}
	if got := meta["a"]; got.Alias != "workshop-pc" || got.Note != "" {
		t.Errorf("meta = %+v, want alias workshop-pc and empty note", got)
	}
}

func TestPruneEventsDropsOldRowsOnly(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	old := time.Now().Add(-100 * 24 * time.Hour)
	recent := time.Now().Add(-time.Hour)
	// Alternate states so each observation counts as a transition.
	if _, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: true}}, old); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if _, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: false}}, recent); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}

	n, err := s.PruneEvents(ctx, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d rows, want 1", n)
	}

	events, _ := s.History(ctx, "a", time.Time{})
	if len(events) != 1 || events[0].Online {
		t.Errorf("remaining events = %+v, want the recent offline one", events)
	}
}

// The session key must survive a restart, or every restart logs the user out.
func TestSecretIsStable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.sqlite3")

	gen := func() ([]byte, error) { return []byte("generated-once"), nil }

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first, err := s1.Secret(ctx, "k", gen)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	second, err := s2.Secret(ctx, "k", func() ([]byte, error) { return []byte("should-not-be-used"), nil })
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("secret changed across restart: %q then %q", first, second)
	}
}

// Regression: a device first observed offline has nothing to report. Recording
// a "went offline" event for a device we had never seen implies it had been up
// until that moment, which inflated its uptime to ~100%.
func TestFirstObservationOfflineRecordsNoEvent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	changed, err := s.RecordPoll(ctx, []Observation{{PeerID: "never-up", Online: false}}, time.Now())
	if err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("first offline sighting reported %d changes, want 0", len(changed))
	}

	events, err := s.History(ctx, "never-up", time.Time{})
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("recorded %d events for a never-seen device, want 0", len(events))
	}

	// It must still be tracked, so a later appearance registers as coming up.
	state, _ := s.AllState(ctx)
	if _, ok := state["never-up"]; !ok {
		t.Error("device is absent from device_state; it would never be diffed")
	}
}

// ...and when that device does come up, that first "online" is a real event.
func TestDeviceComingUpAfterSilentStartRecordsEvent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	t0 := time.Now().Add(-time.Hour)

	if _, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: false}}, t0); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	changed, err := s.RecordPoll(ctx, []Observation{{PeerID: "a", Online: true}}, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if len(changed) != 1 || !changed[0].Online {
		t.Fatalf("changes = %+v, want one online transition", changed)
	}

	events, _ := s.History(ctx, "a", time.Time{})
	if len(events) != 1 || !events[0].Online {
		t.Errorf("events = %+v, want a single online event", events)
	}
}

// A device first seen online is a genuine transition and must be recorded.
func TestFirstObservationOnlineRecordsEvent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	changed, err := s.RecordPoll(ctx, []Observation{{PeerID: "up", Online: true}}, time.Now())
	if err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	if len(changed) != 1 {
		t.Fatalf("first online sighting reported %d changes, want 1", len(changed))
	}
	events, _ := s.History(ctx, "up", time.Time{})
	if len(events) != 1 || !events[0].Online {
		t.Errorf("events = %+v, want a single online event", events)
	}
}
