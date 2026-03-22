package main

import (
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

const explainTestPolicyYAML = `
faramesh-version: "1.0"
agent-id: "explain-test"
default_effect: deny
rules:
  - id: permit-safe-http
    match:
      tool: "http/get"
      when: "args.endpoint == 'https://safe.example'"
    effect: permit
    reason_code: RULE_PERMIT
`

func TestRunExplainFound(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, explainTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:       "rec-1",
			AgentID:        "agent-a",
			SessionID:      "sess-1",
			ToolID:         "http/get",
			Effect:         "permit",
			MatchedRuleID:  "permit-safe-http",
			ReasonCode:     "RULE_PERMIT",
			PolicyVersion:  "policy-v1",
			SelectorSnapshot: map[string]any{"endpoint": "https://safe.example"},
			CreatedAt:      time.Date(2026, time.March, 21, 9, 10, 0, 0, time.UTC),
		},
	})

	result, err := runExplain("rec-1", walPath, policyPath)
	if err != nil {
		t.Fatalf("run explain: %v", err)
	}
	if result.RecordID != "rec-1" {
		t.Fatalf("expected record id rec-1, got %q", result.RecordID)
	}
	if result.Effect != "PERMIT" {
		t.Fatalf("expected PERMIT, got %q", result.Effect)
	}
	if result.ReasonCode != "RULE_PERMIT" {
		t.Fatalf("expected RULE_PERMIT, got %q", result.ReasonCode)
	}
	if result.RuleID != "permit-safe-http" {
		t.Fatalf("expected rule id permit-safe-http, got %q", result.RuleID)
	}
	if result.RuleMatch != "http/get" {
		t.Fatalf("expected rule match http/get, got %q", result.RuleMatch)
	}
	if !strings.Contains(result.RuleWhen, "args.endpoint") {
		t.Fatalf("expected rule when context, got %q", result.RuleWhen)
	}
	if result.AgentID != "agent-a" || result.SessionID != "sess-1" || result.ToolID != "http/get" {
		t.Fatalf("unexpected audit fields: %+v", result)
	}
}

func TestRunExplainNotFound(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, explainTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:      "rec-1",
			ToolID:        "http/get",
			Effect:        "PERMIT",
			MatchedRuleID: "permit-safe-http",
			ReasonCode:    "RULE_PERMIT",
			PolicyVersion: "policy-v1",
			CreatedAt:     time.Now().UTC(),
		},
	})

	_, err := runExplain("rec-missing", walPath, policyPath)
	if err == nil {
		t.Fatalf("expected not found error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExplainReadError(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, explainTestPolicyYAML)

	_, err := runExplain("rec-1", dir+"/missing.wal", policyPath)
	if err == nil {
		t.Fatalf("expected not found error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}
