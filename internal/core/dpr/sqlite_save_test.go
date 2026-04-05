package dpr

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreSavePersistsRecord(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "dpr.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	rec := &Record{
		SchemaVersion:     SchemaVersion,
		FPLVersion:        "1.0",
		CARVersion:        "car/1.0",
		RecordID:          "rec-1",
		PrevRecordHash:    GenesisPrevHash("agent-1"),
		AgentID:           "agent-1",
		SessionID:         "sess-1",
		ToolID:            "http/get",
		InterceptAdapter:  "sdk",
		Effect:            "PERMIT",
		MatchedRuleID:     "rule-1",
		ReasonCode:        "RULE_PERMIT",
		PolicyVersion:     "v-test",
		ArgsStructuralSig: "sig-1",
		DegradedMode:      "FULL",
		CreatedAt:         time.Now().UTC(),
	}
	rec.ComputeHash()

	if err := store.Save(rec); err != nil {
		t.Fatalf("save record: %v", err)
	}

	recent, err := store.Recent(10)
	if err != nil {
		t.Fatalf("read recent: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recent))
	}
	if recent[0].RecordID != rec.RecordID {
		t.Fatalf("expected record id %q, got %q", rec.RecordID, recent[0].RecordID)
	}
}
