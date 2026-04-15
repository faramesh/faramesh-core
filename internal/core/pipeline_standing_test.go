package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/faramesh/faramesh-core/internal/core/standing"
)

const standingDeferPolicy = `
faramesh-version: "1.0"
agent-id: "standing-test-agent"

rules:
  - id: defer-high-risk
    match:
      tool: "pay/*"
    effect: defer
    reason: "needs approval"

default_effect: deny
`

func TestStandingGrantConvertsPolicyDeferToPermit(t *testing.T) {
	doc, ver, err := policy.LoadBytes([]byte(standingDeferPolicy))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	reg := standing.NewRegistry()
	p := NewPipeline(Config{
		Engine:    policy.NewAtomicEngine(eng),
		Sessions:  session.NewManager(),
		Defers:    deferwork.NewWorkflow(""),
		Standing:  reg,
	})
	if _, err := p.RegisterStandingGrant(standing.Input{
		AgentID:     "agent-1",
		ToolPattern: "pay/*",
		RuleID:      "defer-high-risk",
		TTL:         time.Hour,
		MaxUses:     1,
		IssuedBy:    "ops",
	}); err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "c1",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "pay/invoice",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("effect = %s (%s) want PERMIT", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.StandingApprovalConsumed {
		t.Fatalf("reason_code = %s want %s", d.ReasonCode, reasons.StandingApprovalConsumed)
	}
	d2 := p.Evaluate(CanonicalActionRequest{
		CallID:    "c2",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "pay/invoice",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d2.Effect != EffectDefer {
		t.Fatalf("second call should defer, got %s", d2.Effect)
	}
}
