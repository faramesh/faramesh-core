package dpr

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWAL_WriteControlReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	if err := wal.WriteControl(&ControlFrame{
		FrameKind: FrameKindRateUpdate,
		AgentID:   "agent-a",
		Tool:      "stripe/*",
		Window:    "minute",
		Count:     3,
		Limit:     10,
	}); err != nil {
		t.Fatal(err)
	}

	var seen int
	if err := wal.ReplayControl(func(f *ControlFrame) error {
		seen++
		if f.FrameKind != FrameKindRateUpdate || f.AgentID != "agent-a" || f.Count != 3 {
			t.Fatalf("unexpected frame: %+v", f)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("want 1 control frame, got %d", seen)
	}

	// DPR replay must skip control frames.
	var dprCount int
	if err := wal.Replay(func(*Record) error {
		dprCount++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if dprCount != 0 {
		t.Fatalf("want 0 dpr records, got %d", dprCount)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestWAL_CompactRetainsLatestControlFrame(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.WriteControl(&ControlFrame{
		FrameKind: FrameKindRateUpdate,
		AgentID:   "a",
		Tool:      "t",
		Window:    "minute",
		Count:     1,
		Limit:     5,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wal.WriteControl(&ControlFrame{
		FrameKind: FrameKindRateUpdate,
		AgentID:   "a",
		Tool:      "t",
		Window:    "minute",
		Count:     4,
		Limit:     5,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wal.Compact(); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := wal.ReplayControl(func(f *ControlFrame) error {
		count = f.Count
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("want latest count 4 after compact, got %d", count)
	}
}
