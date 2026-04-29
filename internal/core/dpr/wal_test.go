package dpr

import (
	"os"
	"path/filepath"
	"strings"
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

func TestWALCompactRetainsLatestRecordsAndRebasesChain(t *testing.T) {
	prevKeepN := walCompactKeepLastN
	prevMaxAge := walCompactMaxAge
	defer func() {
		walCompactKeepLastN = prevKeepN
		walCompactMaxAge = prevMaxAge
	}()
	walCompactKeepLastN = 1
	walCompactMaxAge = 0

	dir := t.TempDir()
	path := filepath.Join(dir, "compact.wal")
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
		CreatedAt:      time.Now().Add(-48 * time.Hour).UTC(),
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
		PrevRecordHash: r1.RecordHash,
		CreatedAt:      time.Now().UTC(),
	}
	r2.ComputeHash()
	if err := w.Write(r2); err != nil {
		t.Fatalf("write r2: %v", err)
	}

	if err := w.Compact(); err != nil {
		t.Fatalf("compact wal: %v", err)
	}

	var records []*Record
	if err := w.ReplayValidated(func(rec *Record) error {
		clone := *rec
		records = append(records, &clone)
		return nil
	}); err != nil {
		t.Fatalf("replay compacted wal: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("compacted wal retained %d records, want 1", len(records))
	}
	if records[0].RecordID != "r2" {
		t.Fatalf("retained record id = %q, want r2", records[0].RecordID)
	}
	if records[0].PrevRecordHash != GenesisPrevHash("a1") {
		t.Fatalf("rebased prev hash = %q, want genesis %q", records[0].PrevRecordHash, GenesisPrevHash("a1"))
	}
}

func TestWALWriteAutoCompactsAboveThreshold(t *testing.T) {
	prevThreshold := walCompactThresholdBytes
	prevKeepN := walCompactKeepLastN
	prevMaxAge := walCompactMaxAge
	defer func() {
		walCompactThresholdBytes = prevThreshold
		walCompactKeepLastN = prevKeepN
		walCompactMaxAge = prevMaxAge
	}()
	walCompactThresholdBytes = 1
	walCompactKeepLastN = 1
	walCompactMaxAge = 0

	dir := t.TempDir()
	path := filepath.Join(dir, "threshold.wal")
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
		CreatedAt:      time.Now().Add(-24 * time.Hour).UTC(),
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
		PrevRecordHash: r1.RecordHash,
		CreatedAt:      time.Now().UTC(),
	}
	r2.ComputeHash()
	if err := w.Write(r2); err != nil {
		t.Fatalf("write r2: %v", err)
	}

	var ids []string
	if err := w.ReplayValidated(func(rec *Record) error {
		ids = append(ids, rec.RecordID)
		return nil
	}); err != nil {
		t.Fatalf("replay after threshold compaction: %v", err)
	}
	if len(ids) != 1 || ids[0] != "r2" {
		t.Fatalf("unexpected ids after threshold compaction: %#v", ids)
	}
}

func TestOpenWALRejectsUnknownFrameVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "versioned.wal")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open wal file: %v", err)
	}
	header := []byte{
		0x4c, 0x41, 0x57, 0x46, // little-endian walFrameMagic
		0x7f,                   // unsupported version
		0x01, 0x00, 0x00, 0x00, // len=1
		0x00, 0x00, 0x00, 0x00, // bogus crc
	}
	if _, err := f.Write(header); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := f.Write([]byte{0x00}); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_ = f.Close()

	_, err = OpenWAL(path)
	if err == nil {
		t.Fatalf("expected OpenWAL to reject unknown WAL version")
	}
	if !strings.Contains(err.Error(), "unknown WAL frame version") {
		t.Fatalf("unexpected OpenWAL error: %v", err)
	}
}

func TestReplayValidatedFinalHashes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "finalhash.wal")
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
		CreatedAt:      time.Now().UTC(),
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
		PrevRecordHash: r1.RecordHash,
		CreatedAt:      time.Now().UTC(),
	}
	r2.ComputeHash()
	if err := w.Write(r2); err != nil {
		t.Fatalf("write r2: %v", err)
	}
	r3 := &Record{
		SchemaVersion:  SchemaVersion,
		RecordID:       "r3",
		AgentID:        "a2",
		SessionID:      "s2",
		ToolID:         "t3",
		PrevRecordHash: GenesisPrevHash("a2"),
		CreatedAt:      time.Now().UTC(),
	}
	r3.ComputeHash()
	if err := w.Write(r3); err != nil {
		t.Fatalf("write r3: %v", err)
	}

	m, err := w.ReplayValidatedFinalHashes()
	if err != nil {
		t.Fatalf("ReplayValidatedFinalHashes: %v", err)
	}
	if m["a1"] != r2.RecordHash {
		t.Fatalf("a1 tip = %q want %q", m["a1"], r2.RecordHash)
	}
	if m["a2"] != r3.RecordHash {
		t.Fatalf("a2 tip = %q want %q", m["a2"], r3.RecordHash)
	}
}
