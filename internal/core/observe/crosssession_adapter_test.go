package observe

import (
	"testing"
	"time"
)

func TestFlowTrackerFromNilAndNoOp(t *testing.T) {
	if FlowTrackerFrom(nil) != nil {
		t.Fatal("expected nil from nil tracker")
	}
	if FlowTrackerFrom(noOpCrossSessionTracker{}) != nil {
		t.Fatal("expected nil from no-op tracker")
	}
}

func TestNewCrossSessionFlowTrackerIsConcrete(t *testing.T) {
	tr := NewCrossSessionFlowTracker()
	ft := FlowTrackerFrom(tr)
	if ft == nil {
		t.Fatal("expected concrete FlowTracker from NewCrossSessionFlowTracker")
	}
	if ft.SuspicionCount() != 0 {
		t.Fatalf("expected zero initial suspicion, got %d", ft.SuspicionCount())
	}
}

func TestGetCrossSessionFlowTrackerDefaultUnset(t *testing.T) {
	orig := Default.crossSessionTracker
	Default.SetCrossSessionTracker(nil)
	defer Default.SetCrossSessionTracker(orig)

	if GetCrossSessionFlowTracker() != nil {
		t.Fatal("expected nil when tracker reset to no-op")
	}
}

func TestGetCrossSessionFlowTrackerWired(t *testing.T) {
	orig := Default.crossSessionTracker
	ft := NewFlowTracker()
	Default.SetCrossSessionTracker(newFlowCrossSessionAdapter(ft))
	defer Default.SetCrossSessionTracker(orig)

	got := GetCrossSessionFlowTracker()
	if got != ft {
		t.Fatal("GetCrossSessionFlowTracker should return wired FlowTracker instance")
	}
}

func TestCrossSessionReadThenExfilDifferentSessions(t *testing.T) {
	ft := NewFlowTracker()
	ts := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)

	_ = ft.RecordAccess(AccessEvent{
		PrincipalID: "user-1",
		SessionID:   "sess-a",
		ToolID:      "vault/read_secret",
		Timestamp:   ts,
		DPRID:       "dpr-1",
	})
	_ = ft.RecordAccess(AccessEvent{
		PrincipalID: "user-1",
		SessionID:   "sess-b",
		ToolID:      "slack/post_message",
		Timestamp:   ts.Add(time.Minute),
		DPRID:       "dpr-2",
	})

	if ft.SuspicionCount() != 1 {
		t.Fatalf("expected 1 cross-session suspicion, got %d", ft.SuspicionCount())
	}
}

func TestCrossSessionSameSessionNoSuspicion(t *testing.T) {
	ft := NewFlowTracker()
	ts := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)

	_ = ft.RecordAccess(AccessEvent{
		PrincipalID: "user-1",
		SessionID:   "sess-a",
		ToolID:      "db/query",
		Timestamp:   ts,
	})
	_ = ft.RecordAccess(AccessEvent{
		PrincipalID: "user-1",
		SessionID:   "sess-a",
		ToolID:      "slack/post_message",
		Timestamp:   ts.Add(time.Minute),
	})

	if ft.SuspicionCount() != 0 {
		t.Fatalf("expected 0 suspicion same session, got %d", ft.SuspicionCount())
	}
}
