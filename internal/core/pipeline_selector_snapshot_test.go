package core

import (
	"testing"
)

func TestSelectorSnapshotForRecordPreservesUsefulArgs(t *testing.T) {
	got := selectorSnapshotForRecord(map[string]any{
		"input": map[string]any{
			"target_agent_id":  "worker-b",
			"delegation_scope": "safe/read",
			"delegation_ttl":   "30m",
		},
		"amount": 1200,
	})
	if got == nil {
		t.Fatalf("expected selector snapshot")
	}
	input, ok := got["input"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested input map, got %#v", got["input"])
	}
	if input["target_agent_id"] != "worker-b" {
		t.Fatalf("expected target_agent_id to survive, got %#v", input["target_agent_id"])
	}
	if input["delegation_scope"] != "safe/read" {
		t.Fatalf("expected delegation_scope to survive, got %#v", input["delegation_scope"])
	}
	if input["delegation_ttl"] != "30m" {
		t.Fatalf("expected delegation_ttl to survive, got %#v", input["delegation_ttl"])
	}
	if got["amount"] != 1200 {
		t.Fatalf("expected amount to survive, got %#v", got["amount"])
	}
}

func TestSelectorSnapshotForRecordRedactsSensitiveValues(t *testing.T) {
	got := selectorSnapshotForRecord(map[string]any{
		"scope":         "payments",
		"api_key":       "sk-super-secret-token-value",
		"authorization": "Bearer top-secret",
		"path":          "/etc/passwd",
		"nested": map[string]any{
			"client_secret": "very-secret",
			"note":          "safe",
		},
	})
	if got == nil {
		t.Fatalf("expected selector snapshot")
	}
	if got["scope"] != "payments" {
		t.Fatalf("expected non-sensitive scope preserved, got %#v", got["scope"])
	}
	if got["api_key"] != "[redacted]" {
		t.Fatalf("expected api_key redacted, got %#v", got["api_key"])
	}
	if got["authorization"] != "[redacted]" {
		t.Fatalf("expected authorization redacted, got %#v", got["authorization"])
	}
	if got["path"] != "/etc/passwd" {
		t.Fatalf("expected path preserved for replayable scanner context, got %#v", got["path"])
	}
	nested, ok := got["nested"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map, got %#v", got["nested"])
	}
	if nested["client_secret"] != "[redacted]" {
		t.Fatalf("expected nested client_secret redacted, got %#v", nested["client_secret"])
	}
	if nested["note"] != "safe" {
		t.Fatalf("expected safe nested note preserved, got %#v", nested["note"])
	}
}
