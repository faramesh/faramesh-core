package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const strictModelPolicy = `
faramesh-version: "1.0"
agent-id: "model-agent"
vars:
  model_name: "gpt-4o"
rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "allowed"
default_effect: deny
`

type modelCaptureWAL struct {
	last *dpr.Record
}

func (w *modelCaptureWAL) Write(rec *dpr.Record) error {
	w.last = rec
	return nil
}

func (w *modelCaptureWAL) Close() error { return nil }

func buildStrictModelPipeline(t *testing.T, wal dpr.Writer) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(strictModelPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:                  policy.NewAtomicEngine(eng),
		WAL:                     wal,
		Sessions:                session.NewManager(),
		Defers:                  deferwork.NewWorkflow(""),
		StrictModelVerification: true,
	})
}

func TestStrictModelVerificationDeniesWhenRuntimeModelMissing(t *testing.T) {
	p := buildStrictModelPipeline(t, &modelCaptureWAL{})
	p.RegisterModelIdentity("gpt-4o", "abc123", "openai", "2026-03")

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "model-missing",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "http/get",
		Args:      map[string]any{"url": "https://example.com"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected DENY when runtime model is missing, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.IdentityUnverified {
		t.Fatalf("expected reason %s, got %s", reasons.IdentityUnverified, d.ReasonCode)
	}
}

func TestStrictModelVerificationDeniesFingerprintMismatch(t *testing.T) {
	p := buildStrictModelPipeline(t, &modelCaptureWAL{})
	p.RegisterModelIdentity("gpt-4o", "abc123", "openai", "2026-03")

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "model-mismatch",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "http/get",
		Args:      map[string]any{"url": "https://example.com"},
		Model: &ModelIdentity{
			Name:        "gpt-4o",
			Fingerprint: "deadbeef",
			Provider:    "openai",
			Version:     "2026-03",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected DENY for fingerprint mismatch, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.IdentityUnverified {
		t.Fatalf("expected reason %s, got %s", reasons.IdentityUnverified, d.ReasonCode)
	}
}

func TestStrictModelVerificationPersistsDPREvidence(t *testing.T) {
	wal := &modelCaptureWAL{}
	p := buildStrictModelPipeline(t, wal)
	p.RegisterModelIdentity("gpt-4o", "abc123", "openai", "2026-03")

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "model-ok",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "http/get",
		Args:      map[string]any{"url": "https://example.com"},
		Model: &ModelIdentity{
			Name:        "gpt-4o",
			Fingerprint: "abc123",
			Provider:    "openai",
			Version:     "2026-03",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected PERMIT for verified model identity, got %s (%s)", d.Effect, d.Reason)
	}
	if wal.last == nil {
		t.Fatalf("expected DPR record to be written")
	}
	if wal.last.OperatorResults == nil {
		t.Fatalf("expected operator_results evidence in DPR")
	}
	entry, ok := wal.last.OperatorResults["model_identity_verification"]
	if !ok {
		t.Fatalf("expected model_identity_verification evidence in DPR")
	}
	payload, ok := entry.(map[string]any)
	if !ok {
		t.Fatalf("expected model evidence payload map, got %T", entry)
	}
	verified, _ := payload["verified"].(bool)
	if !verified {
		t.Fatalf("expected verified=true in DPR evidence payload: %#v", payload)
	}
}
