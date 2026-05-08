package schedule

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "schedules.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSQLiteStore_OpenAndMigrate(t *testing.T) {
	openTestStore(t) // covers MkdirAll + migrate
}

func TestSQLiteStore_RejectsEmptyPath(t *testing.T) {
	if _, err := OpenSQLiteStore(""); err == nil {
		t.Error("expected error on empty path")
	}
}

func TestSQLiteStore_InsertGetRoundtrip(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	e := ScheduledExecution{
		ID: "sched_x", AgentID: "a", Tool: "stripe/refund", Args: `{"amount":500}`,
		Policy: "payment-bot", Reeval: true,
		ScheduledAt: now.Add(time.Hour), CreatedAt: now,
		Status: StatusPendingApproval, StatusMessage: "needs ops review",
	}
	if err := store.Insert(e); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, ok := store.GetByID("sched_x")
	if !ok {
		t.Fatal("missing after insert")
	}
	if got.AgentID != "a" || got.Tool != "stripe/refund" || got.Args != `{"amount":500}` {
		t.Errorf("scalar mismatch: %+v", got)
	}
	if got.Reeval != true || got.Status != StatusPendingApproval {
		t.Errorf("status/reeval mismatch: %+v", got)
	}
	if !got.ScheduledAt.Equal(now.Add(time.Hour)) {
		t.Errorf("time mismatch: %v vs %v", got.ScheduledAt, now.Add(time.Hour))
	}
	if !got.ExecutedAt.IsZero() {
		t.Errorf("executed_at should be zero, got %v", got.ExecutedAt)
	}
}

func TestSQLiteStore_RejectsDuplicateID(t *testing.T) {
	store := openTestStore(t)
	e := ScheduledExecution{ID: "dup", AgentID: "a", Tool: "t/op", Status: StatusScheduled}
	if err := store.Insert(e); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := store.Insert(e); !errors.Is(err, ErrDuplicateID) {
		t.Errorf("expected ErrDuplicateID, got %v", err)
	}
}

func TestSQLiteStore_ListByAgent_OrderingAndFilter(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	mustInsertSched(t, store, ScheduledExecution{ID: "a2", AgentID: "a", Tool: "t/op", ScheduledAt: now.Add(2 * time.Hour), Status: StatusScheduled})
	mustInsertSched(t, store, ScheduledExecution{ID: "a1", AgentID: "a", Tool: "t/op", ScheduledAt: now.Add(time.Hour), Status: StatusScheduled})
	mustInsertSched(t, store, ScheduledExecution{ID: "x", AgentID: "x", Tool: "t/op", ScheduledAt: now, Status: StatusScheduled})

	got := store.ListByAgent("a")
	if len(got) != 2 || got[0].ID != "a1" {
		t.Errorf("expected [a1, a2] for agent=a, got %v", got)
	}
}

func TestSQLiteStore_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "schedules.db")
	now := time.Now().UTC().Truncate(time.Second)

	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Insert(ScheduledExecution{ID: "persist", AgentID: "a", Tool: "t/op", ScheduledAt: now, CreatedAt: now, Status: StatusScheduled}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	got, ok := reopened.GetByID("persist")
	if !ok {
		t.Fatal("did not survive reopen")
	}
	if !got.ScheduledAt.Equal(now) {
		t.Errorf("post-reopen time mismatch: %v vs %v", got.ScheduledAt, now)
	}
}

func TestSQLiteStore_BackedService(t *testing.T) {
	store := openTestStore(t)
	clk := func() time.Time { return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC) }
	counter := 0
	gen := func() string {
		counter++
		return "sched_" + strconv.Itoa(counter)
	}
	svc := NewService(store, clk, gen)

	a, err := svc.Create(CreateRequest{Tool: "stripe/refund", Agent: "agent", At: "+1h"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got, ok := svc.Inspect(a.ID); !ok || got.Tool != "stripe/refund" {
		t.Errorf("inspect mismatch: ok=%v %+v", ok, got)
	}
	if list := svc.List("agent"); len(list) != 1 {
		t.Errorf("expected 1 in list, got %d", len(list))
	}

	// Approval lifecycle through the SQLite-backed service.
	if _, err := svc.MarkPendingApproval(a.ID, "policy defer"); err != nil {
		t.Fatalf("mark pending: %v", err)
	}
	if pend := svc.Pending(); len(pend) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pend))
	}
	if _, err := svc.Approve(a.ID, "ops"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Executed history.
	if _, err := svc.MarkExecuted(a.ID, true, ""); err != nil {
		t.Fatalf("mark executed: %v", err)
	}
	if hist := svc.History(time.Hour); len(hist) != 1 {
		t.Errorf("expected 1 in history, got %d", len(hist))
	}
}

func mustInsertSched(t *testing.T, s Store, e ScheduledExecution) {
	t.Helper()
	if err := s.Insert(e); err != nil {
		t.Fatalf("insert %s: %v", e.ID, err)
	}
}
