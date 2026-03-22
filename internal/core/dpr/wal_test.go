package dpr

import (
	"strings"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWALReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	r1 := &Record{SchemaVersion: SchemaVersion, RecordID: "r1", AgentID: "a1", ToolID: "t1", CreatedAt: time.Now()}
	r2 := &Record{SchemaVersion: SchemaVersion, RecordID: "r2", AgentID: "a1", ToolID: "t2", CreatedAt: time.Now()}
	if err := w.Write(r1); err != nil {
		t.Fatalf("write r1: %v", err)
	}
	if err := w.Write(r2); err != nil {
		t.Fatalf("write r2: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	w, err = OpenWAL(path)
	if err != nil {
		t.Fatalf("reopen wal: %v", err)
	}
	defer w.Close()
	var ids []string
	if err := w.Replay(func(rec *Record) error {
		ids = append(ids, rec.RecordID)
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(ids) != 2 || ids[0] != "r1" || ids[1] != "r2" {
		t.Fatalf("unexpected replay ids: %#v", ids)
	}
}

func TestWALRecoversFromTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	r1 := &Record{SchemaVersion: SchemaVersion, RecordID: "ok", AgentID: "a1", ToolID: "t1", CreatedAt: time.Now()}
	if err := w.Write(r1); err != nil {
		t.Fatalf("write r1: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	// Append a torn frame tail.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("append torn: %v", err)
	}
	if _, err := f.Write([]byte{0x46, 0x57, 0x41, 0x4c, 0x10, 0x00}); err != nil {
		t.Fatalf("write torn bytes: %v", err)
	}
	_ = f.Close()

	w, err = OpenWAL(path)
	if err != nil {
		t.Fatalf("reopen wal with recovery: %v", err)
	}
	defer w.Close()
	var ids []string
	if err := w.Replay(func(rec *Record) error {
		ids = append(ids, rec.RecordID)
		return nil
	}); err != nil {
		t.Fatalf("replay after recovery: %v", err)
	}
	if len(ids) != 1 || ids[0] != "ok" {
		t.Fatalf("unexpected ids after recovery: %#v", ids)
	}
}

func TestReplayValidatedDetectsInvalidGenesis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer w.Close()

	r := &Record{
		SchemaVersion:  SchemaVersion,
		RecordID:       "bad-genesis",
		AgentID:        "a1",
		SessionID:      "s1",
		ToolID:         "t1",
		PrevRecordHash: "not-genesis",
		CreatedAt:      time.Now(),
	}
	r.ComputeHash()
	if err := w.Write(r); err != nil {
		t.Fatalf("write invalid genesis: %v", err)
	}
	err = w.ReplayValidated(func(rec *Record) error { return nil })
	if err == nil {
		t.Fatalf("expected replay validation error for invalid genesis")
	}
	if !strings.Contains(err.Error(), "invalid genesis marker") {
		t.Fatalf("unexpected replay error: %v", err)
	}
}

func TestReplayValidatedDetectsBrokenChainStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	w, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer w.Close()

	r1 := &Record{
		SchemaVersion:  SchemaVersion,
		RecordID:       "r1",
		AgentID:        "a1",
		SessionID:      "s1",
		ToolID:         "t1",
		PrevRecordHash: GenesisPrevHash("a1"),
		CreatedAt:      time.Now(),
	}
	r1.ComputeHash()
	if err := w.Write(r1); err != nil {
		t.Fatalf("write r1: %v", err)
	}
	r2 := &Record{
		SchemaVersion:  SchemaVersion,
		RecordID:       "r2",
		AgentID:        "a1",
		SessionID:      "s1",
		ToolID:         "t2",
		PrevRecordHash: "broken-prev",
		CreatedAt:      time.Now(),
	}
	r2.ComputeHash()
	if err := w.Write(r2); err != nil {
		t.Fatalf("write r2: %v", err)
	}

	err = w.ReplayValidated(func(rec *Record) error { return nil })
	if err == nil {
		t.Fatalf("expected replay validation error for broken chain continuity")
	}
	if !strings.Contains(err.Error(), "broken chain") {
		t.Fatalf("unexpected replay error: %v", err)
	}
}
