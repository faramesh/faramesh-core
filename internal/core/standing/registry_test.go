package standing

import (
	"testing"
	"time"
)

func TestRegistryAddConsumeMaxUses(t *testing.T) {
	r := NewRegistry()
	_, err := r.Add(Input{
		AgentID:     "ag1",
		ToolPattern: "billing/*",
		TTL:         time.Hour,
		MaxUses:     1,
		IssuedBy:    "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	g1 := r.TryConsume("ag1", "sess1", "billing/refund", "v1", "rule-pay", now)
	if g1 == nil || g1.Uses != 1 {
		t.Fatalf("first consume: %+v", g1)
	}
	g2 := r.TryConsume("ag1", "sess1", "billing/refund", "v1", "rule-pay", now)
	if g2 != nil {
		t.Fatalf("expected no second consume, got %+v", g2)
	}
}

func TestRegistryRuleBinding(t *testing.T) {
	r := NewRegistry()
	_, err := r.Add(Input{
		AgentID:     "ag1",
		ToolPattern: "t/*",
		RuleID:      "only-this",
		TTL:         time.Hour,
		MaxUses:     0,
		IssuedBy:    "bob",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if r.TryConsume("ag1", "", "t/x", "v", "other-rule", now) != nil {
		t.Fatal("should not match wrong rule")
	}
	if r.TryConsume("ag1", "", "t/x", "v", "only-this", now) == nil {
		t.Fatal("expected match")
	}
}
