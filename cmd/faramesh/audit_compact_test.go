package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

func TestRunAuditCompactValidatesChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-compact.wal")
	w, err := dpr.OpenWAL(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	r := &dpr.Record{
		SchemaVersion:  dpr.SchemaVersion,
		RecordID:       "r1",
		AgentID:        "agent",
		SessionID:      "sess",
		ToolID:         "tool/x",
		PrevRecordHash: dpr.GenesisPrevHash("agent"),
		CreatedAt:      time.Now().UTC(),
	}
	r.ComputeHash()
	if err := w.Write(r); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := runAuditCompact(nil, []string{path}); err != nil {
		t.Fatalf("runAuditCompact: %v", err)
	}
}
