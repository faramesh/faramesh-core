package schedule

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

func newTestService(t *testing.T) (*Service, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	counter := 0
	gen := func() string {
		counter++
		return "sched_" + strconv.Itoa(counter)
	}
	return NewService(NewMemoryStore(), clk.Now, gen), clk
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestService_Create_Defaults(t *testing.T) {
	svc, _ := newTestService(t)
	e, err := svc.Create(CreateRequest{Tool: "t/op", Agent: "a"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if e.Status != StatusScheduled {
		t.Errorf("expected StatusScheduled, got %s", e.Status)
	}
	if e.ID == "" {
		t.Error("expected generated ID")
	}
	if !e.ScheduledAt.Equal(e.CreatedAt) {
		t.Errorf("default scheduled_at should equal created_at when --at is empty")
	}
}

func TestService_Create_RejectsMissingFields(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Create(CreateRequest{Tool: "", Agent: "a"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest on empty tool, got %v", err)
	}
	if _, err := svc.Create(CreateRequest{Tool: "t/op", Agent: ""}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest on empty agent, got %v", err)
	}
}

func TestService_Create_ParsesRelativeTime(t *testing.T) {
	svc, clk := newTestService(t)
	e, err := svc.Create(CreateRequest{Tool: "t/op", Agent: "a", At: "+30m"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	want := clk.Now().Add(30 * time.Minute)
	if !e.ScheduledAt.Equal(want.UTC()) {
		t.Errorf("scheduled_at = %v, want %v", e.ScheduledAt, want)
	}
}

func TestService_Create_ParsesRFC3339(t *testing.T) {
	svc, _ := newTestService(t)
	target := "2026-12-31T23:59:00Z"
	e, err := svc.Create(CreateRequest{Tool: "t/op", Agent: "a", At: target})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	want, _ := time.Parse(time.RFC3339, target)
	if !e.ScheduledAt.Equal(want) {
		t.Errorf("scheduled_at = %v, want %v", e.ScheduledAt, want)
	}
}

func TestService_Create_ParsesDays(t *testing.T) {
	svc, clk := newTestService(t)
	e, err := svc.Create(CreateRequest{Tool: "t/op", Agent: "a", At: "+2d"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	want := clk.Now().Add(48 * time.Hour)
	if !e.ScheduledAt.Equal(want.UTC()) {
		t.Errorf("scheduled_at = %v, want %v", e.ScheduledAt, want)
	}
}

func TestService_Create_RejectsInvalidTime(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.Create(CreateRequest{Tool: "t/op", Agent: "a", At: "garbage"}); !errors.Is(err, ErrInvalidTime) {
		t.Errorf("expected ErrInvalidTime, got %v", err)
	}
	if _, err := svc.Create(CreateRequest{Tool: "t/op", Agent: "a", At: "+0s"}); !errors.Is(err, ErrInvalidTime) {
		t.Errorf("expected ErrInvalidTime on zero duration, got %v", err)
	}
}

func TestService_CancelLifecycle(t *testing.T) {
	svc, _ := newTestService(t)
	e, _ := svc.Create(CreateRequest{Tool: "t/op", Agent: "a", At: "+1h"})

	cancelled, err := svc.Cancel(e.ID)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if cancelled.Status != StatusCancelled {
		t.Errorf("expected StatusCancelled, got %s", cancelled.Status)
	}

	// Cancelling again is invalid.
	if _, err := svc.Cancel(e.ID); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("expected ErrInvalidStatus on double-cancel, got %v", err)
	}

	// Cancelling missing returns ErrNotFound.
	if _, err := svc.Cancel("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_ApprovalFlow(t *testing.T) {
	svc, _ := newTestService(t)
	e, _ := svc.Create(CreateRequest{Tool: "t/op", Agent: "a", At: "+1h"})

	// Cannot approve a scheduled (non-pending) item.
	if _, err := svc.Approve(e.ID, "ops"); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("expected ErrInvalidStatus, got %v", err)
	}

	// Move to pending_approval (executor would do this).
	pending, err := svc.MarkPendingApproval(e.ID, "policy deferred")
	if err != nil {
		t.Fatalf("mark pending: %v", err)
	}
	if pending.Status != StatusPendingApproval || pending.StatusMessage != "policy deferred" {
		t.Errorf("unexpected pending state: %+v", pending)
	}

	// Now approve succeeds.
	approved, err := svc.Approve(e.ID, "ops-team")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.Status != StatusApproved || approved.ApprovedBy != "ops-team" {
		t.Errorf("unexpected approved state: %+v", approved)
	}
	if approved.ApprovedAt.IsZero() {
		t.Error("expected approved_at to be set")
	}
}

func TestService_PendingAndHistory(t *testing.T) {
	svc, clk := newTestService(t)
	a, _ := svc.Create(CreateRequest{Tool: "t/op", Agent: "agent", At: "+1h"})
	b, _ := svc.Create(CreateRequest{Tool: "t/op", Agent: "agent", At: "+2h"})
	c, _ := svc.Create(CreateRequest{Tool: "t/op", Agent: "agent", At: "+3h"})

	if _, err := svc.MarkPendingApproval(a.ID, ""); err != nil {
		t.Fatalf("mark pending a: %v", err)
	}
	if _, err := svc.MarkPendingApproval(b.ID, ""); err != nil {
		t.Fatalf("mark pending b: %v", err)
	}
	pending := svc.Pending()
	if len(pending) != 2 {
		t.Errorf("expected 2 pending, got %d", len(pending))
	}

	// Execute c, advance time, check history window.
	if _, err := svc.MarkExecuted(c.ID, true, "ok"); err != nil {
		t.Fatalf("mark executed: %v", err)
	}
	clk.Advance(30 * time.Minute)
	hist := svc.History(time.Hour)
	if len(hist) != 1 || hist[0].ID != c.ID {
		t.Errorf("expected [c] in history, got %v", hist)
	}

	// Older than window: nothing.
	clk.Advance(2 * time.Hour)
	if got := svc.History(30 * time.Minute); len(got) != 0 {
		t.Errorf("expected empty history outside window, got %v", got)
	}
}

func TestService_MarkExecuted_FailsRecordsStatus(t *testing.T) {
	svc, _ := newTestService(t)
	e, _ := svc.Create(CreateRequest{Tool: "t/op", Agent: "a"})
	got, err := svc.MarkExecuted(e.ID, false, "tool error")
	if err != nil {
		t.Fatalf("mark executed: %v", err)
	}
	if got.Status != StatusFailed || got.StatusMessage != "tool error" {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestParseRelativeDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30m", 30 * time.Minute, true},
		{"1h", time.Hour, true},
		{"1d", 24 * time.Hour, true},
		{"2d3h", 51 * time.Hour, true},
		{"junk", 0, false},
	}
	for _, c := range cases {
		got, err := parseRelativeDuration(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("parseRelativeDuration(%q) errored: %v", c.in, err)
			} else if got != c.want {
				t.Errorf("parseRelativeDuration(%q) = %v, want %v", c.in, got, c.want)
			}
		} else if err == nil {
			t.Errorf("parseRelativeDuration(%q) expected error", c.in)
		}
	}
}
