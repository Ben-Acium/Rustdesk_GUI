package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "app.sqlite3"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A device with no report is the normal case, so it must not be an error.
func TestIntelAbsentIsNotAnError(t *testing.T) {
	s := newStore(t)
	raw, at, err := s.Intel(t.Context(), "nobody")
	if err != nil {
		t.Fatalf("Intel: %v", err)
	}
	if raw != nil || !at.IsZero() {
		t.Errorf("got %q at %v, want nil and the zero time", raw, at)
	}
}

func TestIntelReplacesRatherThanAccumulates(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	then := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.SetIntel(ctx, "dev1", then, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetIntel(ctx, "dev1", now, []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}

	raw, at, err := s.Intel(ctx, "dev1")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"v":2}` {
		t.Errorf("report = %s, want the second one", raw)
	}
	if !at.Equal(now) {
		t.Errorf("collected_at = %v, want %v", at, now)
	}

	ages, err := s.IntelCollectedAt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ages) != 1 || !ages["dev1"].Equal(now) {
		t.Errorf("ages = %v", ages)
	}
}

func TestArchiveIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	for i := 0; i < 2; i++ {
		if err := s.SetArchived(ctx, "dev1", true); err != nil {
			t.Fatalf("archive #%d: %v", i, err)
		}
	}
	ids, err := s.ArchivedIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || !ids["dev1"] {
		t.Errorf("archived = %v", ids)
	}

	// Restoring one that was never archived must also succeed.
	if err := s.SetArchived(ctx, "never-archived", false); err != nil {
		t.Errorf("restoring an unarchived device: %v", err)
	}
}

// Forgetting one device must not disturb another.
func TestForgetDeviceLeavesOtherDevicesAlone(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Now().UTC()

	for _, id := range []string{"keep", "drop"} {
		if err := s.SetMeta(ctx, id, Meta{Alias: id}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetIntel(ctx, id, now, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := s.SetDeviceSecret(ctx, id, []byte("sealed")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RecordPoll(ctx, []Observation{
		{PeerID: "keep", Online: true}, {PeerID: "drop", Online: true},
	}, now); err != nil {
		t.Fatal(err)
	}

	if err := s.ForgetDevice(ctx, "drop"); err != nil {
		t.Fatal(err)
	}

	meta, err := s.AllMeta(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, gone := meta["drop"]; gone {
		t.Error("the forgotten device kept its name")
	}
	if _, kept := meta["keep"]; !kept {
		t.Error("forgetting one device erased another")
	}

	state, err := s.AllState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, gone := state["drop"]; gone {
		t.Error("the forgotten device kept its presence state")
	}
	if _, kept := state["keep"]; !kept {
		t.Error("forgetting one device erased another's presence")
	}

	events, err := s.History(ctx, "drop", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Errorf("the forgotten device kept %d history events", len(events))
	}
	if events, _ = s.History(ctx, "keep", now.Add(-time.Hour)); len(events) == 0 {
		t.Error("forgetting one device erased another's history")
	}
}
