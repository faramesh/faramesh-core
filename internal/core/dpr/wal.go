package dpr

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WAL is an append-only, fsync-on-write log of DPR records.
// Records are binary-framed JSON: each frame has a 13-byte header
// (magic uint32 0x4657414c little-endian on disk + version + payload length + CRC32)
// followed by JSON payload.
// A sync is called after every write so that the record is durable
// before the decision is returned to the caller.
//
// WAL ORDERING INVARIANT: Write() blocks until the record is fsynced.
// The pipeline must call Write() before returning the Decision to the adapter.
// If Write() returns an error, the pipeline returns DENY.
type WAL struct {
	mu   sync.Mutex
	file *os.File
	path string
}

const (
	walFrameMagic = uint32(0x4657414c) // "FWAL"
	walVersion    = byte(1)
	walHeaderSize = 13 // magic(4) + version(1) + len(4) + crc32(4)
)

var (
	walCompactThresholdBytes int64         = 16 << 20
	walCompactKeepLastN      int           = 10_000
	walCompactMaxAge         time.Duration = 7 * 24 * time.Hour
	errUnknownWALVersion                   = errors.New("unknown WAL frame version")
)

// OpenWAL opens (or creates) the WAL file at the given path.
// The directory is created if it does not exist.
func OpenWAL(walPath string) (*WAL, error) {
	if err := os.MkdirAll(filepath.Dir(walPath), 0o755); err != nil {
		return nil, fmt.Errorf("create WAL directory: %w", err)
	}
	f, err := os.OpenFile(walPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open WAL %q: %w", walPath, err)
	}
	// Recover from torn/truncated tail records and sync durable boundary.
	if err := recoverWALTail(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &WAL{file: f, path: walPath}, nil
}

// Write appends a record to the WAL and calls fsync before returning.
// This must be called before the decision is delivered to the adapter.
func (w *WAL) Write(rec *Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal DPR record: %w", err)
	}

	var hdr [walHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], walFrameMagic)
	hdr[4] = walVersion
	binary.LittleEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[9:13], crc32.ChecksumIEEE(payload))

	if _, err := w.file.Write(hdr[:]); err != nil {
		return fmt.Errorf("write WAL header: %w", err)
	}
	if _, err := w.file.Write(payload); err != nil {
		return fmt.Errorf("write WAL: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("fsync WAL: %w", err)
	}
	if walCompactThresholdBytes > 0 {
		if info, statErr := w.file.Stat(); statErr == nil && info.Size() >= walCompactThresholdBytes {
			if err := w.compactLocked(); err != nil {
				return fmt.Errorf("compact WAL: %w", err)
			}
		}
	}
	return nil
}

// Close flushes and closes the WAL file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.file.Sync(); err != nil {
		return err
	}
	return w.file.Close()
}

// Path returns the filesystem path of the WAL file.
func (w *WAL) Path() string { return w.path }

// Compact rotates the active WAL and rewrites a compacted WAL that retains the
// most recent records or records still within the retention window.
func (w *WAL) Compact() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.compactLocked()
}

// Replay iterates all valid WAL records in order.
func (w *WAL) Replay(fn func(*Record) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek WAL start: %w", err)
	}
	for {
		rec, err := readNextRecord(w.file)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	_, _ = w.file.Seek(0, io.SeekEnd)
	return nil
}

// ReplayValidated iterates all WAL records in order while enforcing DPR chain
// invariants per agent:
//   - first record must use deterministic genesis marker prev hash
//   - each record hash must match canonical bytes
//   - non-genesis records must link to previous record hash
func (w *WAL) ReplayValidated(fn func(*Record) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek WAL start: %w", err)
	}
	lastHashByAgent := make(map[string]string)
	for idx := 0; ; idx++ {
		rec, err := readNextRecord(w.file)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := validateReplayChainRecord(rec, lastHashByAgent); err != nil {
			return fmt.Errorf("dpr replay validation failed at frame %d record_id=%q agent_id=%q: %w", idx, rec.RecordID, rec.AgentID, err)
		}
		lastHashByAgent[rec.AgentID] = rec.RecordHash
		if err := fn(rec); err != nil {
			return err
		}
	}
	_, _ = w.file.Seek(0, io.SeekEnd)
	return nil
}

// ReplayValidatedFinalHashes returns the last RecordHash observed per AgentID
// after a full validated WAL replay. Used at pipeline startup to compare the
// on-disk WAL chain tip against SQLite-seeded chain hashes (non-fatal drift log).
func (w *WAL) ReplayValidatedFinalHashes() (map[string]string, error) {
	lastByAgent := make(map[string]string)
	err := w.ReplayValidated(func(rec *Record) error {
		lastByAgent[rec.AgentID] = rec.RecordHash
		return nil
	})
	return lastByAgent, err
}

// NullWAL is a WAL that discards all writes, used for in-memory/demo mode.
type NullWAL struct{}

func (n *NullWAL) Write(*Record) error { return nil }
func (n *NullWAL) Close() error        { return nil }

// Writer is the interface satisfied by both WAL and NullWAL.
type Writer interface {
	Write(*Record) error
	Close() error
}

func recoverWALTail(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek WAL for recovery: %w", err)
	}
	var goodOffset int64
	for {
		start, _ := f.Seek(0, io.SeekCurrent)
		_, err := readNextRecord(f)
		if err == io.EOF {
			goodOffset = start
			break
		}
		if err != nil {
			if errors.Is(err, errUnknownWALVersion) {
				return err
			}
			// Corrupt/torn frame tail: truncate to last known-good boundary.
			if truncErr := f.Truncate(start); truncErr != nil {
				return fmt.Errorf("truncate WAL on recovery: %w", truncErr)
			}
			goodOffset = start
			break
		}
		goodOffset, _ = f.Seek(0, io.SeekCurrent)
	}
	if _, err := f.Seek(goodOffset, io.SeekStart); err != nil {
		return fmt.Errorf("seek WAL recovered offset: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync recovered WAL: %w", err)
	}
	_, _ = f.Seek(0, io.SeekEnd)
	return nil
}

func readNextRecord(r io.Reader) (*Record, error) {
	var hdr [walHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read WAL header: %w", err)
	}
	magic := binary.LittleEndian.Uint32(hdr[0:4])
	if magic != walFrameMagic {
		return nil, fmt.Errorf("invalid WAL frame magic")
	}
	version := hdr[4]
	if version != walVersion {
		return nil, errUnknownWALVersion
	}
	n := binary.LittleEndian.Uint32(hdr[5:9])
	wantCRC := binary.LittleEndian.Uint32(hdr[9:13])
	if n == 0 || n > 8*1024*1024 {
		return nil, fmt.Errorf("invalid WAL frame size %d", n)
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("truncated WAL payload")
		}
		return nil, fmt.Errorf("read WAL payload: %w", err)
	}
	gotCRC := crc32.ChecksumIEEE(payload)
	if gotCRC != wantCRC {
		return nil, fmt.Errorf("WAL CRC mismatch")
	}
	var rec Record
	if err := json.Unmarshal(payload, &rec); err != nil {
		return nil, fmt.Errorf("decode WAL record: %w", err)
	}
	return &rec, nil
}

func validateReplayChainRecord(rec *Record, lastHashByAgent map[string]string) error {
	if rec == nil {
		return fmt.Errorf("nil DPR record")
	}
	if rec.AgentID == "" {
		return fmt.Errorf("missing agent_id")
	}
	if rec.RecordHash == "" {
		return fmt.Errorf("missing record_hash")
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256(rec.CanonicalBytes()))
	if rec.RecordHash != wantHash {
		return fmt.Errorf("record_hash mismatch")
	}
	if prev, ok := lastHashByAgent[rec.AgentID]; ok {
		if rec.PrevRecordHash != prev {
			return fmt.Errorf("broken chain: prev_record_hash=%q want=%q", rec.PrevRecordHash, prev)
		}
		return nil
	}
	genesis := GenesisPrevHash(rec.AgentID)
	if rec.PrevRecordHash != genesis {
		return fmt.Errorf("invalid genesis marker: prev_record_hash=%q want=%q", rec.PrevRecordHash, genesis)
	}
	return nil
}

func (w *WAL) compactLocked() error {
	records, err := readAllRecords(w.file)
	if err != nil {
		return err
	}
	retained := retainRecords(records, walCompactKeepLastN, walCompactMaxAge, time.Now().UTC())
	if len(retained) == len(records) {
		if _, err := w.file.Seek(0, io.SeekEnd); err != nil {
			return fmt.Errorf("seek WAL end after compaction scan: %w", err)
		}
		return nil
	}

	archivePath := fmt.Sprintf("%s.%d.bak", w.path, time.Now().UTC().UnixNano())
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close WAL before rotation: %w", err)
	}
	if err := os.Rename(w.path, archivePath); err != nil {
		return fmt.Errorf("rotate WAL to %q: %w", archivePath, err)
	}

	newFile, err := os.OpenFile(w.path, os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open compacted WAL %q: %w", w.path, err)
	}
	w.file = newFile

	lastHashByAgent := make(map[string]string)
	for _, rec := range retained {
		clone := *rec
		clone.HMACSig = ""
		prev := lastHashByAgent[clone.AgentID]
		if prev == "" {
			prev = GenesisPrevHash(clone.AgentID)
		}
		clone.PrevRecordHash = prev
		clone.ComputeHash()
		lastHashByAgent[clone.AgentID] = clone.RecordHash
		if err := writeFrame(w.file, &clone); err != nil {
			return fmt.Errorf("rewrite compacted WAL: %w", err)
		}
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("fsync compacted WAL: %w", err)
	}
	if _, err := w.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek compacted WAL end: %w", err)
	}
	return nil
}

func readAllRecords(f *os.File) ([]*Record, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek WAL start: %w", err)
	}
	var records []*Record
	for {
		rec, err := readNextRecord(f)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

func retainRecords(records []*Record, keepLastN int, maxAge time.Duration, now time.Time) []*Record {
	if len(records) == 0 {
		return nil
	}
	if keepLastN <= 0 {
		keepLastN = len(records)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	start := 0
	if len(records) > keepLastN {
		start = len(records) - keepLastN
	}
	retained := append([]*Record(nil), records[start:]...)
	if maxAge <= 0 {
		return retained
	}
	cutoff := now.Add(-maxAge)
	firstRecent := -1
	for i, rec := range records {
		if !rec.CreatedAt.IsZero() && !rec.CreatedAt.Before(cutoff) {
			firstRecent = i
			break
		}
	}
	if firstRecent >= 0 && firstRecent < start {
		retained = append([]*Record(nil), records[firstRecent:]...)
	}
	return retained
}

func writeFrame(f *os.File, rec *Record) error {
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal DPR record: %w", err)
	}
	var hdr [walHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], walFrameMagic)
	hdr[4] = walVersion
	binary.LittleEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[9:13], crc32.ChecksumIEEE(payload))
	if _, err := f.Write(hdr[:]); err != nil {
		return fmt.Errorf("write WAL header: %w", err)
	}
	if _, err := f.Write(payload); err != nil {
		return fmt.Errorf("write WAL: %w", err)
	}
	return nil
}
