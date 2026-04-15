package toolinventory

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

func TestStoreRecordObservationAndSeed(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tool-inventory.db"))
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	if err := store.RecordObservation(Observation{
		ToolID:           "shell/exec",
		Effect:           "DENY",
		InterceptAdapter: "sdk",
		PolicyRuleID:     "deny-shell",
		CoverageTier:     "B",
		Timestamp:        now,
	}); err != nil {
		t.Fatalf("RecordObservation() error = %v", err)
	}
	if err := store.RecordObservation(Observation{
		ToolID:           "shell/exec",
		Effect:           "PERMIT",
		InterceptAdapter: "proxy",
		PolicyRuleID:     "permit-shell",
		CoverageTier:     "A",
		Timestamp:        now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("RecordObservation() second error = %v", err)
	}
	if err := store.SeedFromDPRRecords([]*dpr.Record{{
		ToolID:           "http/request",
		Effect:           "PERMIT",
		InterceptAdapter: "mcp",
		MatchedRuleID:    "permit-http",
		CreatedAt:        now.Add(2 * time.Minute),
	}}); err != nil {
		t.Fatalf("SeedFromDPRRecords() error = %v", err)
	}

	entries, err := store.All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}

	var shell Entry
	for _, entry := range entries {
		if entry.ToolID == "shell/exec" {
			shell = entry
		}
	}
	if shell.TotalInvocations != 2 {
		t.Fatalf("shell invocations = %d, want 2", shell.TotalInvocations)
	}
	if shell.Effects["DENY"] != 1 || shell.Effects["PERMIT"] != 1 {
		t.Fatalf("shell effects = %#v, want deny=1 permit=1", shell.Effects)
	}
	if len(shell.InterceptAdapters) != 2 {
		t.Fatalf("shell intercept adapters = %#v, want 2", shell.InterceptAdapters)
	}
	if shell.CoverageTier != "A" {
		t.Fatalf("shell coverage tier = %q, want A", shell.CoverageTier)
	}
}
