package dpr

import (
	"os"
	"testing"
	"time"
)

// Integration: set FARAMESH_TEST_POSTGRES_DSN (e.g. postgres://user:pass@localhost:5432/faramesh_test?sslmode=disable)
// and ensure the database exists. CI skips by default; run locally or add a Postgres service to the workflow.

func TestPGStoreSaveAndByID(t *testing.T) {
	dsn := os.Getenv("FARAMESH_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set FARAMESH_TEST_POSTGRES_DSN to run PostgreSQL DPR integration test")
	}
	s, err := OpenPGStore(dsn)
	if err != nil {
		t.Fatalf("OpenPGStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	rec := &Record{
		SchemaVersion:     SchemaVersion,
		RecordID:          "test-pg-" + time.Now().UTC().Format("20060102150405.000000000"),
		PrevRecordHash:    GenesisPrevHash("agent-pg-test"),
		RecordHash:        "hash-integration-test",
		AgentID:           "agent-pg-test",
		SessionID:         "sess-pg",
		ToolID:            "test/tool",
		InterceptAdapter:  "test",
		Effect:            "PERMIT",
		MatchedRuleID:     "r1",
		ReasonCode:        "RULE_PERMIT",
		Reason:            "ok",
		PolicyVersion:     "abc123",
		ArgsStructuralSig: "sig",
		CreatedAt:         time.Now().UTC(),
	}
	if err := s.Save(rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.ByID(rec.RecordID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got == nil || got.RecordID != rec.RecordID || got.Effect != rec.Effect {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
