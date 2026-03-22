package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const runtimeGovPolicy = `
faramesh-version: "1.0"
agent-id: "runtime-gov-agent"

tools:
  risky/write:
    reversibility: irreversible
    blast_radius: external
  safe/read:
    reversibility: reversible
    blast_radius: local

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "permit"

default_effect: deny
`

func buildRuntimeGovPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(runtimeGovPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	loopGov := multiagent.NewLoopGovernor()
	loopGov.ConfigureRuntime(multiagent.LoopRuntimeConfig{
		Enabled:    true,
		Window:     30 * time.Second,
		MaxRepeats: 2,
		MaxCalls:   5,
	})
	aggGov := multiagent.NewAggregationGovernor(multiagent.AggregatePolicy{})
	aggGov.ConfigureRuntime(multiagent.AggregationRuntimeConfig{
		Enabled:         true,
		Window:          time.Minute,
		MaxRiskyActions: 3,
	})
	return NewPipeline(Config{
		Engine:         policy.NewAtomicEngine(eng),
		Sessions:       session.NewManager(),
		Defers:         deferwork.NewWorkflow(""),
		LoopGovernor:   loopGov,
		AggregationGov: aggGov,
	})
}

func runtimeReq(callID, tool string, ts time.Time) CanonicalActionRequest {
	return CanonicalActionRequest{
		CallID:    callID,
		AgentID:   "runtime-agent",
		SessionID: "runtime-session",
		ToolID:    tool,
		Args: map[string]any{
			"x": 1,
		},
		Timestamp: ts,
	}
}

func TestLoopGovernorRepetitionBoundary(t *testing.T) {
	p := buildRuntimeGovPipeline(t)
	base := time.Now()

	d1 := p.Evaluate(runtimeReq("loop-1", "safe/read", base))
	if d1.Effect != EffectPermit {
		t.Fatalf("first call should permit, got %s", d1.Effect)
	}
	d2 := p.Evaluate(runtimeReq("loop-2", "safe/read", base.Add(time.Second)))
	if d2.Effect != EffectPermit {
		t.Fatalf("second repetitive call should permit at boundary, got %s", d2.Effect)
	}
	d3 := p.Evaluate(runtimeReq("loop-3", "safe/read", base.Add(2*time.Second)))
	if d3.Effect != EffectDeny {
		t.Fatalf("third repetitive call should deny, got %s", d3.Effect)
	}
	if d3.ReasonCode != reasons.LoopDetection {
		t.Fatalf("loop repetition deny reason: want %s, got %s", reasons.LoopDetection, d3.ReasonCode)
	}
}

func TestLoopGovernorBurstBoundary(t *testing.T) {
	p := buildRuntimeGovPipeline(t)
	base := time.Now()

	for i := 0; i < 5; i++ {
		d := p.Evaluate(CanonicalActionRequest{
			CallID:    "burst-ok-" + time.Now().Format("150405.000000"),
			AgentID:   "burst-agent",
			SessionID: "burst-session",
			ToolID:    "safe/read",
			Args:      map[string]any{"x": i},
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
		if d.Effect != EffectPermit {
			t.Fatalf("burst call %d should permit, got %s", i+1, d.Effect)
		}
	}

	deny := p.Evaluate(CanonicalActionRequest{
		CallID:    "burst-deny",
		AgentID:   "burst-agent",
		SessionID: "burst-session",
		ToolID:    "safe/read",
		Args:      map[string]any{"x": 99},
		Timestamp: base.Add(6 * time.Second),
	})
	if deny.Effect != EffectDeny {
		t.Fatalf("6th burst call should deny, got %s", deny.Effect)
	}
	if deny.ReasonCode != reasons.AgentLoopDetected {
		t.Fatalf("burst deny reason: want %s, got %s", reasons.AgentLoopDetected, deny.ReasonCode)
	}
}

func TestAggregationGovernorRiskBudgetBoundary(t *testing.T) {
	p := buildRuntimeGovPipeline(t)
	base := time.Now()

	permit := p.Evaluate(runtimeReq("agg-1", "risky/write", base))
	if permit.Effect != EffectPermit {
		t.Fatalf("first risky action should permit at budget boundary, got %s", permit.Effect)
	}

	deny := p.Evaluate(runtimeReq("agg-2", "risky/write", base.Add(time.Second)))
	if deny.Effect != EffectDeny {
		t.Fatalf("second risky action should deny when over budget, got %s", deny.Effect)
	}
	if deny.ReasonCode != reasons.AggregateBudgetExceeded {
		t.Fatalf("aggregation deny reason: want %s, got %s", reasons.AggregateBudgetExceeded, deny.ReasonCode)
	}
}

func TestAggregationGovernorIgnoresNonRiskyTools(t *testing.T) {
	p := buildRuntimeGovPipeline(t)
	base := time.Now()
	for i := 0; i < 8; i++ {
		d := p.Evaluate(CanonicalActionRequest{
			CallID:    "agg-safe-" + time.Now().Format("150405.000000"),
			AgentID:   "agg-safe-agent",
			SessionID: "agg-safe-session",
			ToolID:    "safe/read",
			Args:      map[string]any{"x": i},
			Timestamp: base.Add(time.Duration(i) * 31 * time.Second),
		})
		if d.Effect != EffectPermit {
			t.Fatalf("non-risky call should not consume risk budget, got %s (%s)", d.Effect, d.Reason)
		}
	}
}
