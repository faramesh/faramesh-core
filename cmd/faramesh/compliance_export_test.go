package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

func TestComplianceExportSmoke(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "dpr.wal")
	outPath := filepath.Join(dir, "bundle.json")

	w, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	now := time.Now().UTC()
	r1 := &dpr.Record{
		SchemaVersion: dpr.SchemaVersion,
		RecordID:      "rec-1",
		AgentID:       "agent-a",
		ToolID:        "tool-x",
		CreatedAt:     now,
	}
	r1.ComputeHash()
	r2 := &dpr.Record{
		SchemaVersion: dpr.SchemaVersion,
		RecordID:      "rec-2",
		AgentID:       "agent-a",
		ToolID:        "tool-y",
		CreatedAt:     now.Add(time.Second),
	}
	r2.ComputeHash()
	if err := w.Write(r1); err != nil {
		t.Fatalf("write r1: %v", err)
	}
	if err := w.Write(r2); err != nil {
		t.Fatalf("write r2: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	complianceExportWALPath = walPath
	complianceExportOutPath = outPath
	if err := runComplianceExport(nil, nil); err != nil {
		t.Fatalf("run compliance export: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var bundle dpr.ComplianceExportBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("decode output: %v", err)
	}

	if bundle.SchemaVersion != dpr.ComplianceExportSchema {
		t.Fatalf("unexpected schema version: %q", bundle.SchemaVersion)
	}
	if !bundle.Status.Success {
		t.Fatalf("expected success=true, got errors=%v", bundle.Status.Errors)
	}
	if bundle.Summary.RecordCount != 2 {
		t.Fatalf("unexpected record_count: %d", bundle.Summary.RecordCount)
	}
	if bundle.Checkpoint.TreeSize != 2 || bundle.Checkpoint.MerkleRoot == "" {
		t.Fatalf("checkpoint missing tree/root: %+v", bundle.Checkpoint)
	}
	if len(bundle.Proofs.Inclusion) != 2 {
		t.Fatalf("expected 2 inclusion verifications, got %d", len(bundle.Proofs.Inclusion))
	}
	for i, proof := range bundle.Proofs.Inclusion {
		if !proof.Success {
			t.Fatalf("expected inclusion proof %d to verify: %+v", i, proof)
		}
	}
	if bundle.Proofs.Consistency == nil || !bundle.Proofs.Consistency.Success {
		t.Fatalf("expected consistency proof success, got %+v", bundle.Proofs.Consistency)
	}
}
