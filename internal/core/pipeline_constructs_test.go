package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

func buildPipelineFromFPL(t *testing.T, src string, withRouting bool) *Pipeline {
	t.Helper()
	policyPath := filepath.Join(t.TempDir(), "policy.fpl")
	if err := os.WriteFile(policyPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write temp FPL policy: %v", err)
	}
	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("load FPL policy: %v", err)
	}
	return buildPipelineFromDoc(t, doc, version, withRouting)
}

func buildPipelineFromYAML(t *testing.T, src string) *Pipeline {
	t.Helper()
	doc, version, err := policy.LoadBytes([]byte(src))
	if err != nil {
		t.Fatalf("load YAML policy: %v", err)
	}
	return buildPipelineFromDoc(t, doc, version, false)
}

func buildPipelineFromDoc(t *testing.T, doc *policy.Doc, version string, withRouting bool) *Pipeline {
	t.Helper()
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy engine: %v", err)
	}
	cfg := Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	}
	if withRouting {
		cfg.RoutingGovernor = multiagent.NewRoutingGovernor()
	}
	return NewPipeline(cfg)
}

func TestPipeline_DelegateLoweringEnforcesInvokeTargets(t *testing.T) {
	fplSrc := `
agent orch-1 {
  default deny
  delegate worker-a {
    scope "safe/*"
    ttl 1h
  }
  rules {
    permit invoke_agent
  }
}
`

	p := buildPipelineFromFPL(t, fplSrc, true)

	permitted := p.Evaluate(CanonicalActionRequest{
		CallID:    "delegate-permit",
		AgentID:   "orch-1",
		SessionID: "delegate-session",
		ToolID:    "invoke_agent",
		Args: map[string]any{
			"target_agent_id":  "worker-a",
			"delegation_scope": "safe/read",
			"delegation_ttl":   "30m",
		},
		Timestamp: time.Now().UTC(),
	})
	if permitted.Effect != EffectPermit {
		t.Fatalf("expected delegated target to be permitted, got %s (%s)", permitted.Effect, permitted.Reason)
	}

	missingTTL := p.Evaluate(CanonicalActionRequest{
		CallID:    "delegate-missing-ttl",
		AgentID:   "orch-1",
		SessionID: "delegate-session",
		ToolID:    "invoke_agent",
		Args: map[string]any{
			"target_agent_id":  "worker-a",
			"delegation_scope": "safe/read",
		},
		Timestamp: time.Now().UTC(),
	})
	if missingTTL.Effect != EffectDeny {
		t.Fatalf("missing delegation_ttl should deny delegated invocation, got %s (%s)", missingTTL.Effect, missingTTL.Reason)
	}
	if missingTTL.ReasonCode != reasons.DelegationExceedsAuthority {
		t.Fatalf("want reason code %s, got %s", reasons.DelegationExceedsAuthority, missingTTL.ReasonCode)
	}

	denied := p.Evaluate(CanonicalActionRequest{
		CallID:    "delegate-undeclared-target",
		AgentID:   "orch-1",
		SessionID: "delegate-session",
		ToolID:    "invoke_agent",
		Args: map[string]any{
			"target_agent_id":  "worker-b",
			"delegation_scope": "safe/read",
			"delegation_ttl":   "30m",
		},
		Timestamp: time.Now().UTC(),
	})
	if denied.Effect != EffectDeny {
		t.Fatalf("expected undeclared delegated target to be denied, got %s (%s)", denied.Effect, denied.Reason)
	}
	if denied.ReasonCode != reasons.DelegationExceedsAuthority {
		t.Fatalf("want reason code %s, got %s", reasons.DelegationExceedsAuthority, denied.ReasonCode)
	}
}

func TestPipeline_AmbientMaxCallsPerDayEnforcedPerPrincipal(t *testing.T) {
	fplSrc := `
agent ambient-guard {
  default deny
  ambient {
    max_calls_per_day 1
    on_exceed defer
  }
  rules {
    permit safe/read
  }
}
`

	p := buildPipelineFromFPL(t, fplSrc, false)
	now := time.Now().UTC()
	principalA := &principal.Identity{ID: "principal-a", Verified: true, Method: "spiffe"}
	principalB := &principal.Identity{ID: "principal-b", Verified: true, Method: "spiffe"}

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "ambient-first",
		AgentID:   "ambient-guard",
		SessionID: "ambient-session-a",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Principal: principalA,
		Timestamp: now,
	})
	if first.Effect != EffectPermit {
		t.Fatalf("first call should be permitted, got %s (%s)", first.Effect, first.Reason)
	}

	second := p.Evaluate(CanonicalActionRequest{
		CallID:    "ambient-second",
		AgentID:   "ambient-guard",
		SessionID: "ambient-session-b",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Principal: principalA,
		Timestamp: now.Add(2 * time.Minute),
	})
	if second.Effect != EffectDefer {
		t.Fatalf("second call should exceed ambient principal call limit with DEFER, got %s (%s)", second.Effect, second.Reason)
	}
	if second.ReasonCode != reasons.CrossSessionPrincipalLimit {
		t.Fatalf("want reason code %s, got %s", reasons.CrossSessionPrincipalLimit, second.ReasonCode)
	}

	otherPrincipal := p.Evaluate(CanonicalActionRequest{
		CallID:    "ambient-other-principal",
		AgentID:   "ambient-guard",
		SessionID: "ambient-session-c",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Principal: principalB,
		Timestamp: now.Add(3 * time.Minute),
	})
	if otherPrincipal.Effect != EffectPermit {
		t.Fatalf("separate principal should not inherit another principal's ambient counters, got %s (%s)", otherPrincipal.Effect, otherPrincipal.Reason)
	}
}

func TestPipeline_SelectorLoweringEnforcesContextFreshness(t *testing.T) {
	staleTS := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"updated_at":%q}`, staleTS)))
	}))
	defer server.Close()

	fplSrc := fmt.Sprintf(`
agent selector-agent {
  default deny
  selector ledger {
    source %q
    cache 30s
    on_unavailable deny
    on_timeout defer
  }
  rules {
    permit safe/read
  }
}
`, server.URL)

	p := buildPipelineFromFPL(t, fplSrc, false)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "selector-stale",
		AgentID:   "selector-agent",
		SessionID: "selector-session",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now().UTC(),
	})
	if d.Effect != EffectDefer {
		t.Fatalf("stale selector context should defer, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.ContextStale {
		t.Fatalf("want reason code %s, got %s", reasons.ContextStale, d.ReasonCode)
	}
}

func TestPipeline_PhaseEnforcementCanDeferOutOfPhaseCall(t *testing.T) {
	yamlPolicy := `
faramesh-version: "1.0"
agent-id: "phase-enforcement-agent"

phase_enforcement:
  on_out_of_phase_call: defer

phases:
  intake:
    tools:
      - "safe/read"

rules:
  - id: allow-all
    match:
      tool: "*"
      when: "true"
    effect: permit

default_effect: deny
`

	p := buildPipelineFromYAML(t, yamlPolicy)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "phase-enforcement-defer",
		AgentID:   "phase-enforcement-agent",
		SessionID: "phase-enforcement-session",
		ToolID:    "safe/write",
		Args:      map[string]any{},
		Timestamp: time.Now().UTC(),
	})
	if d.Effect != EffectDefer {
		t.Fatalf("phase enforcement should defer out-of-phase call, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.OutOfPhaseToolCall {
		t.Fatalf("want reason code %s, got %s", reasons.OutOfPhaseToolCall, d.ReasonCode)
	}
}

func TestPipeline_PhaseTransitionPermitMovesToTargetPhase(t *testing.T) {
	yamlPolicy := "faramesh-version: \"1.0\"\n" +
		"agent-id: \"phase-transition-agent\"\n\n" +
		"phases:\n" +
		"  init:\n" +
		"    tools:\n" +
		"      - \"safe/read\"\n" +
		"  execution:\n" +
		"    tools:\n" +
		"      - \"safe/write\"\n\n" +
		"phase_transitions:\n" +
		"  - from: init\n" +
		"    to: execution\n" +
		"    conditions: \"args.promote == true\"\n" +
		"    effect: permit_transition\n" +
		"    reason: \"ready\"\n\n" +
		"rules:\n" +
		"  - id: allow-all\n" +
		"    match:\n" +
		"      tool: \"*\"\n" +
		"      when: \"true\"\n" +
		"    effect: permit\n\n" +
		"default_effect: deny\n"

	p := buildPipelineFromYAML(t, yamlPolicy)

	before := p.Evaluate(CanonicalActionRequest{
		CallID:    "phase-transition-before",
		AgentID:   "phase-transition-agent",
		SessionID: "phase-transition-session",
		ToolID:    "safe/write",
		Args:      map[string]any{"promote": false},
		Timestamp: time.Now().UTC(),
	})
	if before.Effect != EffectDeny {
		t.Fatalf("without transition condition, safe/write should be out-of-phase denied, got %s (%s)", before.Effect, before.Reason)
	}

	after := p.Evaluate(CanonicalActionRequest{
		CallID:    "phase-transition-after",
		AgentID:   "phase-transition-agent",
		SessionID: "phase-transition-session",
		ToolID:    "safe/write",
		Args:      map[string]any{"promote": true},
		Timestamp: time.Now().UTC(),
	})
	if after.Effect != EffectPermit {
		t.Fatalf("transition condition should move agent to execution phase and permit safe/write, got %s (%s)", after.Effect, after.Reason)
	}
}

func TestPipeline_PhaseTransitionDeferBlocksCurrentCall(t *testing.T) {
	yamlPolicy := "faramesh-version: \"1.0\"\n" +
		"agent-id: \"phase-transition-defer-agent\"\n\n" +
		"phases:\n" +
		"  init:\n" +
		"    tools:\n" +
		"      - \"safe/read\"\n" +
		"  execution:\n" +
		"    tools:\n" +
		"      - \"safe/write\"\n\n" +
		"phase_transitions:\n" +
		"  - from: init\n" +
		"    to: execution\n" +
		"    conditions: \"args.approval_required == true\"\n" +
		"    effect: defer\n" +
		"    reason: \"manual transition approval required\"\n\n" +
		"rules:\n" +
		"  - id: allow-all\n" +
		"    match:\n" +
		"      tool: \"*\"\n" +
		"      when: \"true\"\n" +
		"    effect: permit\n\n" +
		"default_effect: deny\n"

	p := buildPipelineFromYAML(t, yamlPolicy)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "phase-transition-defer",
		AgentID:   "phase-transition-defer-agent",
		SessionID: "phase-transition-defer-session",
		ToolID:    "safe/read",
		Args:      map[string]any{"approval_required": true},
		Timestamp: time.Now().UTC(),
	})
	if d.Effect != EffectDefer {
		t.Fatalf("defer transition should defer current call, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.PhaseTransitionDefer {
		t.Fatalf("want reason code %s, got %s", reasons.PhaseTransitionDefer, d.ReasonCode)
	}
}
