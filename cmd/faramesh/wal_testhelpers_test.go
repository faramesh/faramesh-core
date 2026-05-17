package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

func writeReplayTestPolicy(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

func writeReplayTestWAL(t *testing.T, dir string, records []*dpr.Record) string {
	t.Helper()
	path := filepath.Join(dir, "records.wal")
	w, err := dpr.OpenWAL(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	for _, rec := range records {
		if err := w.Write(rec); err != nil {
			t.Fatalf("write record %q: %v", rec.RecordID, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}
	return path
}
