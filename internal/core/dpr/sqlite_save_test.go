package dpr

import (
	"database/sql"
	"errors"
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

func TestOpenStoreConfiguresSQLitePragmas(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "dpr.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	var journalMode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("expected WAL journal mode, got %q", journalMode)
	}

	var busyTimeout int
	if err := store.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if busyTimeout < 5000 {
		t.Fatalf("expected busy_timeout >= 5000, got %d", busyTimeout)
	}

	stats := store.db.Stats()
	if stats.MaxOpenConnections != 1 {
		t.Fatalf("expected MaxOpenConnections = 1, got %d", stats.MaxOpenConnections)
	}
}

func TestIsSQLiteBusyErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "busy code", err: sql.ErrNoRows, want: false},
		{name: "locked text", err: errors.New("database is locked"), want: true},
		{name: "busy token", err: errors.New("SQLITE_BUSY: retry later"), want: true},
		{name: "other text", err: errors.New("boom"), want: false},
	}
	for _, tc := range cases {
		if got := isSQLiteBusyErr(tc.err); got != tc.want {
			t.Fatalf("%s: expected %v, got %v", tc.name, tc.want, got)
		}
	}
}
