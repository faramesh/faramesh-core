package dpr

import (
	"encoding/json"
	"fmt"
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

// OpenWAL opens (or creates) the WAL file at the given path.
// The directory is created if it does not exist.
func OpenWAL(walPath string) (*WAL, error) {
	if err := os.MkdirAll(filepath.Dir(walPath), 0o755); err != nil {
		return nil, fmt.Errorf("create WAL directory: %w", err)
	}
	f, err := os.OpenFile(walPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open WAL %q: %w", walPath, err)
	}
	return &WAL{file: f, path: walPath}, nil
}

// Write appends a record to the WAL and calls fsync before returning.
// This must be called before the decision is delivered to the adapter.
func (w *WAL) Write(rec *Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal DPR record: %w", err)
	}
	line = append(line, '\n')

	if _, err := w.file.Write(line); err != nil {
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

// NullWAL is a WAL that discards all writes, used for in-memory/demo mode.
type NullWAL struct{}

func (n *NullWAL) Write(*Record) error { return nil }
func (n *NullWAL) Close() error        { return nil }

// Writer is the interface satisfied by both WAL and NullWAL.
type Writer interface {
	Write(*Record) error
	Close() error
}
