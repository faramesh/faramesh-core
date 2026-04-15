package deferwork

import (
	"testing"
	"time"
)

func TestTriageClassifyAndEscalateOnce(t *testing.T) {
	triage := NewTriage(TriageConfig{
		DefaultSLA:      5 * time.Minute,
		DefaultPriority: PriorityNormal,
		Rules: []TriageRule{
			{
				ToolPattern:   "payment/*",
				Priority:      PriorityCritical,
				SLA:           120 * time.Millisecond,
				AutoDeny:      false,
				AutoDenyAfter: 90 * time.Millisecond,
				EscalateTo:    "pagerduty",
			},
		},
	})

	item := triage.Classify("tok-critical", "agent-a", "payment/refund", "needs finance approval")
	if item.Priority != PriorityCritical {
		t.Fatalf("priority = %q, want %q", item.Priority, PriorityCritical)
	}
	if item.SLA != 120*time.Millisecond {
		t.Fatalf("sla = %v, want %v", item.SLA, 120*time.Millisecond)
	}
	if item.AutoDeny {
		t.Fatalf("auto_deny = true, want false")
	}
	if item.AutoDenyAfter != 90*time.Millisecond {
		t.Fatalf("auto_deny_after = %v, want %v", item.AutoDenyAfter, 90*time.Millisecond)
	}
	if item.EscalateTo != "pagerduty" {
		t.Fatalf("escalate_to = %q, want pagerduty", item.EscalateTo)
	}

	// Force SLA breach without sleeping so the test stays deterministic.
	item.EscalateAt = time.Now().Add(-1 * time.Second)

	events := triage.CheckEscalations()
	if len(events) != 1 {
		t.Fatalf("escalation events = %d, want 1", len(events))
	}
	if events[0].Item.Token != "tok-critical" {
		t.Fatalf("escalation token = %q, want tok-critical", events[0].Item.Token)
	}
	if events[0].Channel != "pagerduty" {
		t.Fatalf("escalation channel = %q, want pagerduty", events[0].Channel)
	}

	select {
	case chEvent := <-triage.Escalations():
		if chEvent.Item.Token != "tok-critical" {
			t.Fatalf("channel escalation token = %q, want tok-critical", chEvent.Item.Token)
		}
	default:
		t.Fatalf("expected escalation event on channel")
	}

	if next := triage.CheckEscalations(); len(next) != 0 {
		t.Fatalf("second escalation pass emitted %d events, want 0", len(next))
	}
}

func TestTriagePendingSortedOrdersByPriority(t *testing.T) {
	triage := NewTriage(TriageConfig{
		DefaultSLA:      15 * time.Minute,
		DefaultPriority: PriorityNormal,
		Rules: []TriageRule{
			{ToolPattern: "critical/*", Priority: PriorityCritical},
			{ToolPattern: "high/*", Priority: PriorityHigh},
		},
	})

	triage.Classify("tok-normal", "agent-a", "misc/read", "normal")
	triage.Classify("tok-high", "agent-a", "high/write", "high")
	triage.Classify("tok-critical", "agent-a", "critical/delete", "critical")

	items := triage.PendingSorted()
	if len(items) != 3 {
		t.Fatalf("pending count = %d, want 3", len(items))
	}

	order := []string{items[0].Priority, items[1].Priority, items[2].Priority}
	want := []string{PriorityCritical, PriorityHigh, PriorityNormal}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("priority order[%d] = %q, want %q", i, order[i], want[i])
		}
	}
}
