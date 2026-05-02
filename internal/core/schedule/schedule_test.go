package schedule

import (
	"errors"
	"testing"
	"time"
)

func TestMemoryStore_InsertAndGet(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	e := ScheduledExecution{ID: "sched_1", AgentID: "a", Tool: "t/op", ScheduledAt: now, CreatedAt: now, Status: StatusScheduled}
	if err := s.Insert(e); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, ok := s.GetByID("sched_1")
	if !ok || got.AgentID != "a" {
		t.Errorf("retrieve mismatch: %+v ok=%v", got, ok)
	}
}

func TestMemoryStore_RejectsEmptyIDAndDuplicate(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Insert(ScheduledExecution{ID: ""}); err == nil {
		t.Error("expected error on empty id")
	}
	e := ScheduledExecution{ID: "sched_dup", AgentID: "a", Tool: "t/op", Status: StatusScheduled}
	if err := s.Insert(e); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := s.Insert(e); !errors.Is(err, ErrDuplicateID) {
		t.Errorf("expected ErrDuplicateID, got %v", err)
	}
}

func TestMemoryStore_ListByAgent_SoonestFirst(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	_ = s.Insert(ScheduledExecution{ID: "s2", AgentID: "a", Tool: "t/op", ScheduledAt: now.Add(2 * time.Hour), Status: StatusScheduled})
	_ = s.Insert(ScheduledExecution{ID: "s1", AgentID: "a", Tool: "t/op", ScheduledAt: now.Add(time.Hour), Status: StatusScheduled})
	_ = s.Insert(ScheduledExecution{ID: "sx", AgentID: "x", Tool: "t/op", ScheduledAt: now, Status: StatusScheduled})

	got := s.ListByAgent("a")
	if len(got) != 2 || got[0].ID != "s1" || got[1].ID != "s2" {
		t.Errorf("expected [s1, s2], got %v", got)
	}
}

func TestMemoryStore_ListByStatus(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Insert(ScheduledExecution{ID: "p1", Status: StatusPendingApproval, ScheduledAt: time.Now()})
	_ = s.Insert(ScheduledExecution{ID: "p2", Status: StatusPendingApproval, ScheduledAt: time.Now().Add(time.Hour)})
	_ = s.Insert(ScheduledExecution{ID: "s1", Status: StatusScheduled, ScheduledAt: time.Now()})

	pending := s.ListByStatus(StatusPendingApproval)
	if len(pending) != 2 {
		t.Errorf("expected 2 pending, got %d", len(pending))
	}
}

func TestMemoryStore_ListExecutedSince_NewestFirst(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	_ = s.Insert(ScheduledExecution{ID: "old", Status: StatusExecuted, ExecutedAt: now.Add(-2 * time.Hour)})
	_ = s.Insert(ScheduledExecution{ID: "new", Status: StatusExecuted, ExecutedAt: now.Add(-30 * time.Minute)})
	_ = s.Insert(ScheduledExecution{ID: "skip", Status: StatusScheduled})

	got := s.ListExecutedSince(now.Add(-time.Hour))
	if len(got) != 1 || got[0].ID != "new" {
		t.Errorf("expected [new], got %v", got)
	}
}

func TestMemoryStore_Update(t *testing.T) {
	s := NewMemoryStore()
	e := ScheduledExecution{ID: "u1", AgentID: "a", Status: StatusScheduled}
	_ = s.Insert(e)
	e.Status = StatusCancelled
	if err := s.Update(e); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := s.GetByID("u1")
	if got.Status != StatusCancelled {
		t.Errorf("status not updated: %v", got.Status)
	}
	if err := s.Update(ScheduledExecution{ID: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
