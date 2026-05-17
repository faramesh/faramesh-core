// Package schedule provides persistent scheduled tool executions backing
// the `faramesh schedule` CLI surface.
//
// A ScheduledExecution captures a pending tool call that should run at a
// future time, along with its agent, args, and lifecycle status. The store
// is the source of truth; an executor (added in a follow-on PR) wakes up
// at the scheduled time, re-evaluates policy when requested, and submits
// the call through the governance pipeline.
package schedule

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status enumerates the lifecycle states of a ScheduledExecution.
type Status string

const (
	StatusScheduled       Status = "scheduled"
	StatusPendingApproval Status = "pending_approval"
	StatusApproved        Status = "approved"
	StatusExecuted        Status = "executed"
	StatusFailed          Status = "failed"
	StatusCancelled       Status = "cancelled"
)

// ScheduledExecution is a persisted scheduled tool call.
type ScheduledExecution struct {
	ID            string    `json:"id"`
	AgentID       string    `json:"agent_id"`
	Tool          string    `json:"tool"`
	Args          string    `json:"args,omitempty"`
	Policy        string    `json:"policy,omitempty"`
	Reeval        bool      `json:"reeval"`
	ScheduledAt   time.Time `json:"scheduled_at"`
	CreatedAt     time.Time `json:"created_at"`
	Status        Status    `json:"status"`
	StatusMessage string    `json:"status_message,omitempty"`
	ExecutedAt    time.Time `json:"executed_at,omitzero"`
	ApprovedAt    time.Time `json:"approved_at,omitzero"`
	ApprovedBy    string    `json:"approved_by,omitempty"`
}

// Store is the persistence interface for scheduled executions.
//
// Implementations must be safe for concurrent use.
type Store interface {
	Insert(s ScheduledExecution) error
	GetByID(id string) (ScheduledExecution, bool)
	ListByAgent(agentID string) []ScheduledExecution
	ListByStatus(status Status) []ScheduledExecution
	ListExecutedSince(since time.Time) []ScheduledExecution
	Update(s ScheduledExecution) error
}

// ErrDuplicateID is returned when an ID already exists in the store.
var ErrDuplicateID = errors.New("schedule: duplicate id")

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("schedule: not found")

// MemoryStore is an in-process Store backed by a map. Suitable for tests
// and ephemeral daemons; not durable across restarts.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]ScheduledExecution
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]ScheduledExecution)}
}

func (s *MemoryStore) Insert(e ScheduledExecution) error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("schedule: insert requires non-empty id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[e.ID]; exists {
		return ErrDuplicateID
	}
	s.entries[e.ID] = e
	return nil
}

func (s *MemoryStore) GetByID(id string) (ScheduledExecution, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[id]
	return e, ok
}

// ListByAgent returns scheduled executions for an agent, soonest-first.
func (s *MemoryStore) ListByAgent(agentID string) []ScheduledExecution {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ScheduledExecution
	for _, e := range s.entries {
		if e.AgentID == agentID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ScheduledAt.Before(out[j].ScheduledAt)
	})
	return out
}

// ListByStatus returns scheduled executions matching the given status,
// soonest-first.
func (s *MemoryStore) ListByStatus(status Status) []ScheduledExecution {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ScheduledExecution
	for _, e := range s.entries {
		if e.Status == status {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ScheduledAt.Before(out[j].ScheduledAt)
	})
	return out
}

// ListExecutedSince returns executions whose ExecutedAt is at or after
// `since`. Used by the history view.
func (s *MemoryStore) ListExecutedSince(since time.Time) []ScheduledExecution {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ScheduledExecution
	for _, e := range s.entries {
		if !e.ExecutedAt.IsZero() && !e.ExecutedAt.Before(since) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExecutedAt.After(out[j].ExecutedAt)
	})
	return out
}

// Update replaces an existing record. Returns ErrNotFound if the id does
// not exist.
func (s *MemoryStore) Update(e ScheduledExecution) error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("schedule: update requires non-empty id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[e.ID]; !exists {
		return ErrNotFound
	}
	s.entries[e.ID] = e
	return nil
}
