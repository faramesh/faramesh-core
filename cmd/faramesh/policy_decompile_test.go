package main

import (
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

func TestBuildDecompilePlan_MapsDelegatesSelectorsAmbient(t *testing.T) {
	doc := &policy.Doc{
		AgentID:       "payment-bot",
		DefaultEffect: "deny",
		Rules: []policy.Rule{
			{ID: "r1", Match: policy.Match{Tool: "stripe/refund"}, Effect: "defer"},
		},
		DelegationPolicies: []policy.DelegationPolicy{
			{TargetAgent: "fraud-check-bot", Scope: "refund", TTL: "10m", Ceiling: "$500"},
		},
		ContextGuards: []policy.ContextGuard{
			{Source: "account", Endpoint: "https://context.internal/account", MaxAgeSecs: 60, OnMissing: "deny", OnStale: "defer"},
		},
		CrossSessionGuards: []policy.CrossSessionGuard{
			{Scope: "principal", ToolPattern: "*", Metric: "unique_record_count", Window: "24h", MaxUniqueRecords: 100, OnExceed: "defer"},
		},
	}

	plan := buildDecompilePlan(doc)

	if len(plan.Delegates) != 1 {
		t.Fatalf("expected 1 delegate, got %d", len(plan.Delegates))
	}
	if plan.Delegates[0].TargetAgent != "fraud-check-bot" || plan.Delegates[0].Scope != "refund" || plan.Delegates[0].TTL != "10m" || plan.Delegates[0].Ceiling != "approval" {
		t.Fatalf("unexpected delegate mapping: %+v", plan.Delegates[0])
	}
	if !hasWarning(plan.Warnings, "delegation_policies[0].ceiling") {
		t.Fatalf("expected delegate ceiling warning, got %+v", plan.Warnings)
	}

	if len(plan.Selectors) != 1 {
		t.Fatalf("expected 1 selector, got %d", len(plan.Selectors))
	}
	if plan.Selectors[0].ID != "account" || plan.Selectors[0].Source != "https://context.internal/account" {
		t.Fatalf("unexpected selector identity/source mapping: %+v", plan.Selectors[0])
	}
	if plan.Selectors[0].Cache != "60s" || plan.Selectors[0].OnUnavailable != "deny" || plan.Selectors[0].OnTimeout != "defer" {
		t.Fatalf("unexpected selector policy mapping: %+v", plan.Selectors[0])
	}

	if plan.Ambient == nil {
		t.Fatal("expected ambient mapping, got nil")
	}
	if got := plan.Ambient.Limits["max_customers_per_day"]; got != "100" {
		t.Fatalf("expected max_customers_per_day=100, got %q", got)
	}
	if plan.Ambient.OnExceed != "defer" {
		t.Fatalf("expected ambient on_exceed defer, got %q", plan.Ambient.OnExceed)
	}

	if hasWarning(plan.Warnings, "context_guards are not emitted by current decompiler") {
		t.Fatalf("unexpected legacy warning still present: %+v", plan.Warnings)
	}
	if hasWarning(plan.Warnings, "cross_session_guards are not emitted by current decompiler") {
		t.Fatalf("unexpected legacy warning still present: %+v", plan.Warnings)
	}
}

func TestBuildDecompilePlan_CrossSessionBytesAndUnsupportedShapeWarnings(t *testing.T) {
	doc := &policy.Doc{
		AgentID:       "agent",
		DefaultEffect: "deny",
		Rules: []policy.Rule{
			{ID: "r1", Match: policy.Match{Tool: "*"}, Effect: "deny"},
		},
		CrossSessionGuards: []policy.CrossSessionGuard{
			{Scope: "principal", ToolPattern: "*", Metric: "data_volume_bytes", Window: "24h", MaxUniqueRecords: 2 * 1024 * 1024, OnExceed: "deny"},
			{Scope: "principal", ToolPattern: "db/*", Metric: "call_count", Window: "24h", MaxUniqueRecords: 10, OnExceed: "deny"},
		},
	}

	plan := buildDecompilePlan(doc)

	if plan.Ambient == nil {
		t.Fatal("expected ambient mapping, got nil")
	}
	if got := plan.Ambient.Limits["max_data_volume"]; got != "2mb" {
		t.Fatalf("expected max_data_volume=2mb, got %q", got)
	}
	if !hasWarning(plan.Warnings, "tool_pattern") {
		t.Fatalf("expected unsupported tool_pattern warning, got %+v", plan.Warnings)
	}
}

func hasWarning(warnings []string, needle string) bool {
	for _, w := range warnings {
		if strings.Contains(w, needle) {
			return true
		}
	}
	return false
}
