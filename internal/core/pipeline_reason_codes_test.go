package core

import (
	"testing"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

func TestReasonCodeHelpersKnownUnknownAndStrictValidation(t *testing.T) {
	if !reasons.IsKnown(reasons.RuleDeny) {
		t.Fatalf("expected %q to be known", reasons.RuleDeny)
	}
	if reasons.Normalize(reasons.RuleDeny) != reasons.RuleDeny {
		t.Fatalf("expected known code to remain unchanged")
	}
	if reasons.Normalize("NOT_A_REAL_REASON") != reasons.UnknownReasonCode {
		t.Fatalf("expected unknown code normalization to safe code")
	}
	if err := reasons.Validate(reasons.RuleDeny); err != nil {
		t.Fatalf("expected known code to pass strict validation: %v", err)
	}
	if err := reasons.Validate("NOT_A_REAL_REASON"); err == nil {
		t.Fatalf("expected unknown code to fail strict validation")
	}
}

func TestPipelineNormalizesUnknownReasonCodeFromPolicy(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: "reason-agent"
rules:
  - id: deny-with-unknown-code
    match:
      tool: "tool/unsafe"
    effect: deny
    reason_code: NOT_A_REAL_REASON
    reason: "blocked for test"
default_effect: deny
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "reason-normalize-1",
		AgentID:   "agent-1",
		SessionID: "session-1",
		ToolID:    "tool/unsafe",
		Args:      map[string]any{},
	})
	if d.ReasonCode != reasons.UnknownReasonCode {
		t.Fatalf("expected normalized unknown reason code %q, got %q", reasons.UnknownReasonCode, d.ReasonCode)
	}
}
