package dpr

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// WAL is an append-only, fsync-on-write log of DPR records.
// Records are newline-delimited JSON. A sync is called after every write
// so that the record is durable before the decision is returned to the caller.
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
	walHeaderSize = 12                 // magic(4) + len(4) + crc32(4)
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
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[8:12], crc32.ChecksumIEEE(payload))

	if _, err := w.file.Write(hdr[:]); err != nil {
		return fmt.Errorf("write WAL header: %w", err)
	}
	if _, err := w.file.Write(payload); err != nil {
		return fmt.Errorf("write WAL: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("fsync WAL: %w", err)
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
	n := binary.LittleEndian.Uint32(hdr[4:8])
	wantCRC := binary.LittleEndian.Uint32(hdr[8:12])
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
