package multiagent

import (
	"strings"
	"testing"
	"time"
)

func TestHashAggregate_Deterministic(t *testing.T) {
	a := AggregateResult{
		SessionID:   "sess-1",
		Synthesized: "hello world",
		Sources: []AggregationSource{
			{AgentID: "ag1", Output: "a"},
			{AgentID: "ag2", Output: "b"},
		},
	}
	b := AggregateResult{
		SessionID:   "sess-1",
		Synthesized: "hello world",
		Sources: []AggregationSource{
			{AgentID: "ag1", Output: "a"},
			{AgentID: "ag2", Output: "b"},
		},
	}
	if HashAggregate(a) != HashAggregate(b) {
		t.Fatal("hash should be stable for same aggregate")
	}
	if HashAggregate(a) == HashAggregate(AggregateResult{SessionID: "x"}) {
		t.Fatal("hash should differ for different content")
	}
}

func TestGovernOutput_MinSources(t *testing.T) {
	ag := NewAggregationGovernor(AggregatePolicy{MinSources: 2})
	_, _, err := ag.GovernOutput(AggregateResult{
		SessionID:   "s",
		Synthesized: "ok",
		Sources:     []AggregationSource{{AgentID: "a1", Output: "x"}},
	})
	if err == nil || !strings.Contains(err.Error(), "AGGREGATION_INCOMPLETE") {
		t.Fatalf("expected incomplete error, got %v", err)
	}
}

func TestGovernOutput_EmailRedaction(t *testing.T) {
	ag := NewAggregationGovernor(AggregatePolicy{
		MinSources:         1,
		BlockedEntityTypes: []string{"email"},
	})
	out, entities, err := ag.GovernOutput(AggregateResult{
		SessionID:   "s",
		Synthesized: "Contact me at user@example.com please",
		Sources:     []AggregationSource{{AgentID: "a1", Output: "x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "user@example.com") {
		t.Fatalf("email should be redacted: %q", out)
	}
	if len(entities) == 0 {
		t.Fatal("expected entity extraction")
	}
}

func TestGovernOutput_MaxLength(t *testing.T) {
	ag := NewAggregationGovernor(AggregatePolicy{
		MinSources:        1,
		MaxOutputLength:   20,
	})
	long := strings.Repeat("x", 100)
	out, _, err := ag.GovernOutput(AggregateResult{
		SessionID:   "s",
		Synthesized: long,
		Sources:     []AggregationSource{{AgentID: "a1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= 20 || !strings.Contains(out, "TRUNCATED") {
		t.Fatalf("expected truncation, got len=%d", len(out))
	}
}

func TestAggregationGovernor_CheckAndTrack(t *testing.T) {
	ag := NewAggregationGovernor(AggregatePolicy{})
	ag.ConfigureRuntime(AggregationRuntimeConfig{
		Enabled:         true,
		Window:          time.Minute,
		MaxRiskyActions: 5,
	})
	now := time.Now()
	ok, code, _ := ag.CheckAndTrack("sess", 3, now)
	if !ok || code != "" {
		t.Fatalf("first track should pass: ok=%v code=%q", ok, code)
	}
	ok2, code2, _ := ag.CheckAndTrack("sess", 3, now)
	if ok2 || code2 != "AGGREGATE_BUDGET_EXCEEDED" {
		t.Fatalf("expected budget exceeded: ok=%v code=%q", ok2, code2)
	}
}
