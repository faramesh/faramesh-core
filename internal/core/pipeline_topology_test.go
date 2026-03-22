package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const topologyPolicy = `
faramesh-version: "1.0"
agent-id: "orch-1"
default_effect: deny
orchestrator_manifest:
  agent_id: "orch-1"
  undeclared_invocation_policy: deny
  permitted_invocations:
    - agent_id: "worker-a"
      max_invocations_per_session: 10
rules:
  - id: allow-invoke
    match:
      tool: "multiagent/invoke_agent"
    effect: permit
`

func TestPipeline_TopologyInvokeDeniedUndeclaredTarget(t *testing.T) {
	doc, ver, err := policy.LoadBytes([]byte(topologyPolicy))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	rg := multiagent.NewRoutingGovernor()
	p := NewPipeline(Config{
		Engine:          policy.NewAtomicEngine(eng),
		RoutingGovernor: rg,
		Sessions:        session.NewManager(),
		Defers:          deferwork.NewWorkflow(""),
	})
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "c1",
		AgentID:   "orch-1",
		SessionID: "s1",
		ToolID:    "multiagent/invoke_agent",
		Args:      map[string]any{"target_agent_id": "unknown-worker"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny || d.ReasonCode == "" {
		t.Fatalf("expected deny, got %+v", d)
	}
}

func TestPipeline_TopologyInvokePermitted_FPLManifest(t *testing.T) {
	const pol = `
faramesh-version: "1.0"
agent-id: "orch-1"
default_effect: deny
fpl_inline: |
  manifest orchestrator orch-1 undeclared deny
  manifest grant orch-1 to worker-a max 10
rules:
  - id: allow-invoke
    match:
      tool: "multiagent/invoke_agent"
    effect: permit
`
	doc, ver, err := policy.LoadBytes([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	rg := multiagent.NewRoutingGovernor()
	p := NewPipeline(Config{
		Engine:          policy.NewAtomicEngine(eng),
		RoutingGovernor: rg,
		Sessions:        session.NewManager(),
		Defers:          deferwork.NewWorkflow(""),
	})
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "c-fpl",
		AgentID:   "orch-1",
		SessionID: "s1",
		ToolID:    "multiagent/invoke_agent",
		Args:      map[string]any{"target_agent_id": "worker-a"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %+v", d)
	}
}

func TestPipeline_TopologyInvokePermitted(t *testing.T) {
	doc, ver, err := policy.LoadBytes([]byte(topologyPolicy))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	rg := multiagent.NewRoutingGovernor()
	p := NewPipeline(Config{
		Engine:          policy.NewAtomicEngine(eng),
		RoutingGovernor: rg,
		Sessions:        session.NewManager(),
		Defers:          deferwork.NewWorkflow(""),
	})
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "c2",
		AgentID:   "orch-1",
		SessionID: "s1",
		ToolID:    "multiagent/invoke_agent",
		Args:      map[string]any{"target_agent_id": "worker-a"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %+v", d)
	}
}
