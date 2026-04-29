package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/compensation"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

const compensatePolicyYAML = `
faramesh-version: "1.0"
agent-id: "compensate-test"
default_effect: deny
tools:
  stripe/charge:
    reversibility: compensatable
  cache/invalidate:
    reversibility: reversible
compensation:
  stripe/charge:
    compensation_tool: stripe/refund
    arg_mapping:
      charge_id: "charge_id"
`

func TestBuildCompensateOutputProposed(t *testing.T) {
	engine := buildCompensateEngine(t)
	rec := &dpr.Record{
		RecordID:  "rec-proposed",
		ToolID:    "stripe/charge",
		Effect:    "PERMIT",
		CreatedAt: time.Now().UTC(),
	}
	result := buildCompensateOutput(engine, rec, map[string]any{
		"charge_id": "ch_123",
	})
	if result.Status != "proposed" {
		t.Fatalf("expected proposed status, got %q", result.Status)
	}
	if result.Operation == nil || result.Operation.ToolID != "stripe/refund" {
		t.Fatalf("expected stripe/refund operation, got %+v", result.Operation)
	}
}

func TestBuildCompensateOutputNoCompensation(t *testing.T) {
	engine := buildCompensateEngine(t)
	rec := &dpr.Record{
		RecordID: "rec-reversible",
		ToolID:   "cache/invalidate",
		Effect:   "PERMIT",
	}
	result := buildCompensateOutput(engine, rec, nil)
	if result.Status != "no_compensation" {
		t.Fatalf("expected no_compensation status, got %q", result.Status)
	}
	if result.Operation != nil {
		t.Fatalf("expected nil operation, got %+v", result.Operation)
	}
}

func TestBuildCompensateOutputUnsupported(t *testing.T) {
	engine := buildCompensateEngine(t)
	rec := &dpr.Record{
		RecordID: "rec-unsupported",
		ToolID:   "email/send",
		Effect:   "PERMIT",
	}
	result := buildCompensateOutput(engine, rec, nil)
	if result.Status != "unsupported" {
		t.Fatalf("expected unsupported status, got %q", result.Status)
	}
}

func buildCompensateEngine(t *testing.T) *compensation.Engine {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(compensatePolicyYAML), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return compensation.NewEngine(doc)
}
