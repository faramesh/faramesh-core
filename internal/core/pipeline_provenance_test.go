package core

import (
	"fmt"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const provenancePolicy = `
faramesh-version: "1.0"
agent-id: "provenance-agent"

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "permit"

default_effect: deny
`

type provenanceCaptureWAL struct {
	last *dpr.Record
}

func (w *provenanceCaptureWAL) Write(rec *dpr.Record) error {
	w.last = rec
	return nil
}
func (w *provenanceCaptureWAL) Close() error { return nil }

func buildProvenancePipeline(t *testing.T, wal dpr.Writer, tracker observe.ArgProvenanceTracker) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(provenancePolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:     policy.NewAtomicEngine(eng),
		WAL:        wal,
		Sessions:   session.NewManager(),
		Defers:     deferwork.NewWorkflow(""),
		Provenance: tracker,
	})
}

func TestArgProvenancePopulatesFromTrackedOutput(t *testing.T) {
	wal := &provenanceCaptureWAL{}
	tracker := observe.NewArgProvenanceTracker()
	if err := tracker.RecordToolOutput("agent-prov", "sess-prov", "tool/source", "rec-source-1", "invoice_88421 ready"); err != nil {
		t.Fatalf("seed tracker: %v", err)
	}
	p := buildProvenancePipeline(t, wal, tracker)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "prov-source",
		AgentID:   "agent-prov",
		SessionID: "sess-prov",
		ToolID:    "tool/use",
		Args: map[string]any{
			"memo": "submit invoice_88421 ready for posting",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s", d.Effect)
	}
	if wal.last == nil || wal.last.ArgProvenance == nil {
		t.Fatalf("expected arg provenance in DPR record")
	}
	if got := wal.last.ArgProvenance["memo"]; got != "rec-source-1" {
		t.Fatalf("expected memo provenance rec-source-1, got %q", got)
	}
}

func TestArgProvenanceUnknownStableWhenNoSource(t *testing.T) {
	wal := &provenanceCaptureWAL{}
	p := buildProvenancePipeline(t, wal, observe.NewArgProvenanceTracker())
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "prov-unknown",
		AgentID:   "agent-prov",
		SessionID: "sess-prov",
		ToolID:    "tool/use",
		Args: map[string]any{
			"memo": "totally fresh value",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s", d.Effect)
	}
	if wal.last == nil || wal.last.ArgProvenance == nil {
		t.Fatalf("expected arg provenance in DPR record")
	}
	if got := wal.last.ArgProvenance["memo"]; got != "unknown" {
		t.Fatalf("expected memo provenance unknown, got %q", got)
	}
}

type failingInferProvenanceTracker struct{}

func (failingInferProvenanceTracker) InferArgProvenance(string, string, map[string]any) (map[string]string, error) {
	return nil, fmt.Errorf("boom-infer")
}

func (failingInferProvenanceTracker) RecordToolOutput(string, string, string, string, any) error {
	return nil
}

type failingRecordProvenanceTracker struct{}

func (failingRecordProvenanceTracker) InferArgProvenance(string, string, map[string]any) (map[string]string, error) {
	return map[string]string{"output": "unknown"}, nil
}

func (failingRecordProvenanceTracker) RecordToolOutput(string, string, string, string, any) error {
	return fmt.Errorf("boom-record")
}

func TestArgProvenanceInferenceFailureDenies(t *testing.T) {
	p := buildProvenancePipeline(t, &provenanceCaptureWAL{}, failingInferProvenanceTracker{})
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "prov-infer-fail",
		AgentID:   "agent-prov",
		SessionID: "sess-prov",
		ToolID:    "tool/use",
		Args:      map[string]any{"memo": "abc"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny when arg provenance inference fails, got %s", d.Effect)
	}
	if d.ReasonCode != "TELEMETRY_HOOK_ERROR" {
		t.Fatalf("expected reason code TELEMETRY_HOOK_ERROR, got %q", d.ReasonCode)
	}
}

func TestToolOutputTelemetryFailureDeniesPermitPath(t *testing.T) {
	p := buildProvenancePipeline(t, &provenanceCaptureWAL{}, failingRecordProvenanceTracker{})
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "prov-record-fail",
		AgentID:   "agent-prov",
		SessionID: "sess-prov",
		ToolID:    "tool/use",
		Args:      map[string]any{"output": "materialized"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny when output telemetry fails, got %s", d.Effect)
	}
	if d.ReasonCode != "TELEMETRY_HOOK_ERROR" {
		t.Fatalf("expected reason code TELEMETRY_HOOK_ERROR, got %q", d.ReasonCode)
	}
}
