package schedule

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Clock returns the current time. Injectable for tests.
type Clock func() time.Time

// IDGenerator returns a fresh schedule identifier. Injectable for tests.
type IDGenerator func() string

// Service orchestrates scheduled execution management on top of a Store.
type Service struct {
	store Store
	now   Clock
	newID IDGenerator
}

// NewService wires a Service. If clock is nil, time.Now is used; if newID
// is nil, a 16-byte hex generator with prefix "sched_" is used.
func NewService(store Store, clock Clock, newID IDGenerator) *Service {
	if clock == nil {
		clock = time.Now
	}
	if newID == nil {
		newID = defaultIDGenerator
	}
	return &Service{store: store, now: clock, newID: newID}
}

func defaultIDGenerator() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return "sched_" + hex.EncodeToString(buf)
}

// CreateRequest mirrors the wire body for `schedule create`.
type CreateRequest struct {
	Tool   string `json:"tool"`
	Agent  string `json:"agent"`
	Args   string `json:"args,omitempty"`
	At     string `json:"at,omitempty"`
	Policy string `json:"policy,omitempty"`
	Reeval bool   `json:"reeval"`
}

// Errors surfaced by Service operations.
var (
	ErrInvalidRequest = errors.New("schedule: invalid request")
	ErrInvalidTime    = errors.New("schedule: invalid time")
	ErrInvalidStatus  = errors.New("schedule: invalid status transition")
)

// Create validates the request, parses the scheduled time, and persists a
// new ScheduledExecution. The status is `scheduled` by default; the
// transport layer (added in a follow-on PR) is responsible for moving
// items to `pending_approval` based on policy evaluation outcomes.
func (s *Service) Create(req CreateRequest) (ScheduledExecution, error) {
	tool := strings.TrimSpace(req.Tool)
	agent := strings.TrimSpace(req.Agent)
	if tool == "" || agent == "" {
		return ScheduledExecution{}, fmt.Errorf("%w: tool and agent are required", ErrInvalidRequest)
	}
	at, err := s.parseAt(req.At)
	if err != nil {
		return ScheduledExecution{}, fmt.Errorf("%w: %v", ErrInvalidTime, err)
	}

	now := s.now().UTC()
	e := ScheduledExecution{
		ID:          s.newID(),
		AgentID:     agent,
		Tool:        tool,
		Args:        strings.TrimSpace(req.Args),
		Policy:      strings.TrimSpace(req.Policy),
		Reeval:      req.Reeval,
		ScheduledAt: at.UTC(),
		CreatedAt:   now,
		Status:      StatusScheduled,
	}
	if err := s.store.Insert(e); err != nil {
		return ScheduledExecution{}, err
	}
	return e, nil
}

// List returns scheduled executions for an agent, soonest-first.
func (s *Service) List(agentID string) []ScheduledExecution {
	return s.store.ListByAgent(strings.TrimSpace(agentID))
}

// Inspect returns a stored execution by ID.
func (s *Service) Inspect(id string) (ScheduledExecution, bool) {
	return s.store.GetByID(strings.TrimSpace(id))
}

// Cancel transitions an execution to `cancelled`. Already-executed or
// already-cancelled entries return ErrInvalidStatus.
func (s *Service) Cancel(id string) (ScheduledExecution, error) {
	e, ok := s.store.GetByID(strings.TrimSpace(id))
	if !ok {
		return ScheduledExecution{}, ErrNotFound
	}
	switch e.Status {
	case StatusExecuted, StatusFailed, StatusCancelled:
		return e, fmt.Errorf("%w: cannot cancel from %s", ErrInvalidStatus, e.Status)
	}
	e.Status = StatusCancelled
	if err := s.store.Update(e); err != nil {
		return ScheduledExecution{}, err
	}
	return e, nil
}

// Approve transitions a `pending_approval` execution to `approved`.
// Other states return ErrInvalidStatus.
func (s *Service) Approve(id, approver string) (ScheduledExecution, error) {
	e, ok := s.store.GetByID(strings.TrimSpace(id))
	if !ok {
		return ScheduledExecution{}, ErrNotFound
	}
	if e.Status != StatusPendingApproval {
		return e, fmt.Errorf("%w: can only approve pending_approval, got %s", ErrInvalidStatus, e.Status)
	}
	e.Status = StatusApproved
	e.ApprovedAt = s.now().UTC()
	e.ApprovedBy = strings.TrimSpace(approver)
	if err := s.store.Update(e); err != nil {
		return ScheduledExecution{}, err
	}
	return e, nil
}

// Pending returns all executions awaiting approval, soonest-first.
func (s *Service) Pending() []ScheduledExecution {
	return s.store.ListByStatus(StatusPendingApproval)
}

// History returns executions whose ExecutedAt falls within the last
// `window` duration, newest-first.
func (s *Service) History(window time.Duration) []ScheduledExecution {
	if window <= 0 {
		window = 24 * time.Hour
	}
	since := s.now().Add(-window)
	return s.store.ListExecutedSince(since)
}

// MarkExecuted records the outcome of a scheduled tool call. Used by the
// executor in the follow-on transport PR.
func (s *Service) MarkExecuted(id string, success bool, message string) (ScheduledExecution, error) {
	e, ok := s.store.GetByID(strings.TrimSpace(id))
	if !ok {
		return ScheduledExecution{}, ErrNotFound
	}
	if success {
		e.Status = StatusExecuted
	} else {
		e.Status = StatusFailed
	}
	e.StatusMessage = strings.TrimSpace(message)
	e.ExecutedAt = s.now().UTC()
	if err := s.store.Update(e); err != nil {
		return ScheduledExecution{}, err
	}
	return e, nil
}

// MarkPendingApproval moves a scheduled item to pending_approval. Used by
// the executor when policy evaluation defers at execution time.
func (s *Service) MarkPendingApproval(id, message string) (ScheduledExecution, error) {
	e, ok := s.store.GetByID(strings.TrimSpace(id))
	if !ok {
		return ScheduledExecution{}, ErrNotFound
	}
	if e.Status != StatusScheduled && e.Status != StatusApproved {
		return e, fmt.Errorf("%w: cannot move from %s to pending_approval", ErrInvalidStatus, e.Status)
	}
	e.Status = StatusPendingApproval
	e.StatusMessage = strings.TrimSpace(message)
	if err := s.store.Update(e); err != nil {
		return ScheduledExecution{}, err
	}
	return e, nil
}

// parseAt accepts RFC3339 timestamps and relative durations of the form
// "+30m", "+1h", "+2d". Empty input means "now" (immediate).
func (s *Service) parseAt(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return s.now(), nil
	}
	if strings.HasPrefix(raw, "+") {
		dur, err := parseRelativeDuration(strings.TrimPrefix(raw, "+"))
		if err != nil {
			return time.Time{}, err
		}
		if dur <= 0 {
			return time.Time{}, fmt.Errorf("relative duration must be positive")
		}
		return s.now().Add(dur), nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("must be RFC3339 or +<duration>: %v", err)
	}
	return t, nil
}

// parseRelativeDuration extends time.ParseDuration to accept "d" (days).
// "1d", "2d3h", "5h" all work; bare time.ParseDuration handles everything
// without a "d".
func parseRelativeDuration(raw string) (time.Duration, error) {
	if !strings.Contains(raw, "d") {
		return time.ParseDuration(raw)
	}
	idx := strings.Index(raw, "d")
	var days int
	if _, err := fmt.Sscanf(raw[:idx], "%d", &days); err != nil {
		return 0, fmt.Errorf("invalid days: %v", err)
	}
	d := time.Duration(days) * 24 * time.Hour
	rest := raw[idx+1:]
	if rest == "" {
		return d, nil
	}
	rem, err := time.ParseDuration(rest)
	if err != nil {
		return 0, err
	}
	return d + rem, nil
}
