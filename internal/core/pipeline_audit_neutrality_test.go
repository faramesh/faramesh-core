package core

import (
	"path/filepath"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

// Tests aligned with docs/internal/FARAMESH_PART_A_CONTROL_PLAN.md §3 + archive runtime-truth narrative.
// (former FARAMESH_RUNTIME_TRUTH_IMPLEMENTATION_PLAN.md) §4.5:
// decision outputs should not depend on which durable WAL backend is attached,
// holding policy and request constant (exceptions: WAL write failure path).

func TestPipeline_decisionInvariantToWALBackend_permit(t *testing.T) {
	const yamlPolicy = `
faramesh-version: "1.0"
agent-id: "audit-neutral"
default_effect: deny
rules:
  - id: ok
    match:
      tool: "http/get"
      when: "true"
    effect: permit
    reason_code: RULE_PERMIT
`
	doc, ver, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatal(err)
	}
	engDisk, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	engNull, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}

	walPath := filepath.Join(t.TempDir(), "neutral.wal")
	realWAL, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer realWAL.Close()

	pDisk := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engDisk),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      realWAL,
	})
	pNull := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engNull),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      &dpr.NullWAL{},
	})

	req := CanonicalActionRequest{
		CallID:    "call-neutral-permit",
		AgentID:   "audit-neutral",
		SessionID: "sess-neutral",
		ToolID:    "http/get",
		Args:      map[string]any{"url": "https://example.com"},
		Timestamp: time.Now().UTC(),
	}

	dDisk := pDisk.Evaluate(req)
	dNull := pNull.Evaluate(req)

	if dDisk.Effect != dNull.Effect || reasons.Normalize(dDisk.ReasonCode) != reasons.Normalize(dNull.ReasonCode) {
		t.Fatalf("decision mismatch: disk=%s/%s null=%s/%s", dDisk.Effect, dDisk.ReasonCode, dNull.Effect, dNull.ReasonCode)
	}
	if dDisk.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s (%s)", dDisk.Effect, dDisk.Reason)
	}
}

func TestPipeline_decisionInvariantToWALBackend_unmatchedDeny(t *testing.T) {
	const yamlPolicy = `
faramesh-version: "1.0"
agent-id: "audit-neutral"
default_effect: deny
`
	doc, ver, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatal(err)
	}
	engDisk, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	engNull, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}

	walPath := filepath.Join(t.TempDir(), "neutral-deny.wal")
	realWAL, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer realWAL.Close()

	pDisk := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engDisk),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      realWAL,
	})
	pNull := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engNull),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      &dpr.NullWAL{},
	})

	req := CanonicalActionRequest{
		CallID:    "call-neutral-deny",
		AgentID:   "audit-neutral",
		SessionID: "sess-neutral-deny",
		ToolID:    "shell/run",
		Args:      map[string]any{"cmd": "echo hi"},
		Timestamp: time.Now().UTC(),
	}

	dDisk := pDisk.Evaluate(req)
	dNull := pNull.Evaluate(req)

	if dDisk.Effect != dNull.Effect || reasons.Normalize(dDisk.ReasonCode) != reasons.Normalize(dNull.ReasonCode) {
		t.Fatalf("decision mismatch: disk=%s/%s null=%s/%s", dDisk.Effect, dDisk.ReasonCode, dNull.Effect, dNull.ReasonCode)
	}
	if dDisk.Effect != EffectDeny {
		t.Fatalf("expected deny, got %s (%s)", dDisk.Effect, dDisk.Reason)
	}
}

func TestPipeline_decisionInvariantToWALBackend_defer(t *testing.T) {
	const yamlPolicy = `
faramesh-version: "1.0"
agent-id: "audit-neutral-defer"
default_effect: deny
rules:
  - id: refund-defer
    match:
      tool: "stripe/refund"
      when: "true"
    effect: defer
    reason_code: RULE_DEFER
`
	doc, ver, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatal(err)
	}
	engDisk, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	engNull, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}

	walPath := filepath.Join(t.TempDir(), "neutral-defer.wal")
	realWAL, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer realWAL.Close()

	pDisk := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engDisk),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      realWAL,
	})
	pNull := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engNull),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      &dpr.NullWAL{},
	})

	req := CanonicalActionRequest{
		CallID:    "call-neutral-defer",
		AgentID:   "audit-neutral-defer",
		SessionID: "sess-neutral-defer",
		ToolID:    "stripe/refund",
		Args:      map[string]any{"amount": 50},
		Timestamp: time.Now().UTC(),
	}

	dDisk := pDisk.Evaluate(req)
	dNull := pNull.Evaluate(req)

	if dDisk.Effect != dNull.Effect || reasons.Normalize(dDisk.ReasonCode) != reasons.Normalize(dNull.ReasonCode) {
		t.Fatalf("decision mismatch: disk=%s/%s null=%s/%s", dDisk.Effect, dDisk.ReasonCode, dNull.Effect, dNull.ReasonCode)
	}
	if dDisk.Effect != EffectDefer {
		t.Fatalf("expected defer, got %s (%s)", dDisk.Effect, dDisk.Reason)
	}
}

func TestPipeline_decisionInvariantToWALBackend_shadow(t *testing.T) {
	const yamlPolicy = `
faramesh-version: "1.0"
agent-id: "audit-neutral-shadow"
default_effect: deny
rules:
  - id: shadow-http
    match:
      tool: "http/get"
      when: "true"
    effect: shadow
    reason_code: RULE_SHADOW
`
	doc, ver, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatal(err)
	}
	engDisk, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	engNull, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}

	walPath := filepath.Join(t.TempDir(), "neutral-shadow.wal")
	realWAL, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer realWAL.Close()

	pDisk := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engDisk),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      realWAL,
	})
	pNull := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engNull),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
		WAL:      &dpr.NullWAL{},
	})

	req := CanonicalActionRequest{
		CallID:    "call-neutral-shadow",
		AgentID:   "audit-neutral-shadow",
		SessionID: "sess-neutral-shadow",
		ToolID:    "http/get",
		Args:      map[string]any{"url": "https://example.com"},
		Timestamp: time.Now().UTC(),
	}

	dDisk := pDisk.Evaluate(req)
	dNull := pNull.Evaluate(req)

	if dDisk.Effect != dNull.Effect || reasons.Normalize(dDisk.ReasonCode) != reasons.Normalize(dNull.ReasonCode) {
		t.Fatalf("decision mismatch: disk=%s/%s null=%s/%s", dDisk.Effect, dDisk.ReasonCode, dNull.Effect, dNull.ReasonCode)
	}
	if dDisk.Effect != EffectShadow {
		t.Fatalf("expected shadow, got %s (%s)", dDisk.Effect, dDisk.Reason)
	}
}
