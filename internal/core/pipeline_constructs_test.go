package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/jobs"
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

func TestPipeline_BudgetOnExceedCanDefer(t *testing.T) {
	yamlPolicy := `
faramesh-version: "1.0"
agent-id: "budget-defer-agent"
budget:
  max_calls: 1
  on_exceed: defer
rules:
  - id: allow-safe
    match:
      tool: "safe/read"
    effect: permit
default_effect: deny
`

	doc, version, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{Engine: policy.NewAtomicEngine(eng)})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-first",
		AgentID:   "budget-defer-agent",
		SessionID: "budget-session",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now().UTC(),
	})
	if first.Effect != EffectPermit {
		t.Fatalf("first call should be permitted, got %s (%s)", first.Effect, first.Reason)
	}

	second := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-second",
		AgentID:   "budget-defer-agent",
		SessionID: "budget-session",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now().UTC(),
	})
	if second.Effect != EffectDefer {
		t.Fatalf("second call should defer on budget exceed, got %s (%s)", second.Effect, second.Reason)
	}
	if second.ReasonCode != reasons.SessionToolLimit {
		t.Fatalf("want reason code %s, got %s", reasons.SessionToolLimit, second.ReasonCode)
	}
}

func TestPipeline_TokenBudgetSessionExceeded(t *testing.T) {
	yamlPolicy := `
faramesh-version: "1.0"
agent-id: "tok-budget-agent"
budget:
  session_tokens: 100
rules:
  - id: allow-llm
    match:
      tool: "llm/call"
    effect: permit
default_effect: deny
`

	doc, version, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{Engine: policy.NewAtomicEngine(eng)})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "tok-1",
		AgentID:   "tok-budget-agent",
		SessionID: "tok-session",
		ToolID:    "llm/call",
		Args:      map[string]any{"_faramesh.tokens": int64(60)},
		Timestamp: time.Now().UTC(),
	})
	if first.Effect != EffectPermit {
		t.Fatalf("first call permit, got %s (%s)", first.Effect, first.Reason)
	}

	second := p.Evaluate(CanonicalActionRequest{
		CallID:    "tok-2",
		AgentID:   "tok-budget-agent",
		SessionID: "tok-session",
		ToolID:    "llm/call",
		Args:      map[string]any{"_faramesh.tokens": int64(50)},
		Timestamp: time.Now().UTC(),
	})
	if second.Effect != EffectDeny {
		t.Fatalf("second call should deny on token budget, got %s (%s)", second.Effect, second.Reason)
	}
	if second.ReasonCode != reasons.BudgetSessionTokensExceeded {
		t.Fatalf("reason = %s, want %s", second.ReasonCode, reasons.BudgetSessionTokensExceeded)
	}
}

func TestPipeline_BudgetReservationConfirmsPermitWithoutDoubleCharge(t *testing.T) {
	yamlPolicy := `
faramesh-version: "1.0"
agent-id: "budget-cost-agent"
budget:
  session_usd: 10
tools:
  llm/generate:
    cost_usd: 6
rules:
  - id: allow-costed-tool
    match:
      tool: "llm/generate"
    effect: permit
default_effect: deny
`

	doc, version, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	sessions := session.NewManager()
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: sessions,
		Defers:   deferwork.NewWorkflow(""),
	})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-cost-first",
		AgentID:   "budget-cost-agent",
		SessionID: "budget-cost-session",
		ToolID:    "llm/generate",
		Args:      map[string]any{},
		Timestamp: time.Now().UTC(),
	})
	if first.Effect != EffectPermit {
		t.Fatalf("first call should be permitted, got %s (%s)", first.Effect, first.Reason)
	}
	if got := sessions.Get("budget-cost-agent").CurrentCostUSD(); got != 6 {
		t.Fatalf("current cost after first permit = %v, want 6", got)
	}

	second := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-cost-second",
		AgentID:   "budget-cost-agent",
		SessionID: "budget-cost-session",
		ToolID:    "llm/generate",
		Args:      map[string]any{},
		Timestamp: time.Now().UTC(),
	})
	if second.Effect != EffectDeny {
		t.Fatalf("second call should be denied on reserved budget exceed, got %s (%s)", second.Effect, second.Reason)
	}
	if second.ReasonCode != reasons.BudgetSessionExceeded {
		t.Fatalf("want reason code %s, got %s", reasons.BudgetSessionExceeded, second.ReasonCode)
	}
	if got := sessions.Get("budget-cost-agent").CurrentCostUSD(); got != 6 {
		t.Fatalf("current cost after denied second call = %v, want 6", got)
	}
}

func TestPipeline_BudgetReservationRollsBackDeniedDecision(t *testing.T) {
	yamlPolicy := `
faramesh-version: "1.0"
agent-id: "budget-rollback-agent"
budget:
  session_usd: 10
tools:
  llm/generate:
    cost_usd: 4
rules:
  - id: deny-costed-tool
    match:
      tool: "llm/generate"
    effect: deny
default_effect: deny
`

	doc, version, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	sessions := session.NewManager()
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: sessions,
		Defers:   deferwork.NewWorkflow(""),
	})

	decision := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-rollback-deny",
		AgentID:   "budget-rollback-agent",
		SessionID: "budget-rollback-session",
		ToolID:    "llm/generate",
		Args:      map[string]any{},
		Timestamp: time.Now().UTC(),
	})
	if decision.Effect != EffectDeny {
		t.Fatalf("policy deny should still deny, got %s (%s)", decision.Effect, decision.Reason)
	}
	if got := sessions.Get("budget-rollback-agent").CurrentCostUSD(); got != 0 {
		t.Fatalf("current cost after denied reserved call = %v, want 0", got)
	}
}

func TestPipeline_ModifyEffectCarriesStructuredArgs(t *testing.T) {
	yamlPolicy := `
faramesh-version: "1.0"
agent-id: "modify-agent"
rules:
  - id: "cap-refund"
    match:
      tool: "stripe/refund"
    effect: modify
    modify_args:
      limit: 500
      isolation: docker
    modify_reason: "refund capped by policy"
    modify_required: true
default_effect: deny
`

	doc, version, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{Engine: policy.NewAtomicEngine(eng)})

	decision := p.Evaluate(CanonicalActionRequest{
		CallID:    "modify-call",
		AgentID:   "modify-agent",
		SessionID: "modify-session",
		ToolID:    "stripe/refund",
		Args:      map[string]any{"amount": 1000},
		Timestamp: time.Now().UTC(),
	})

	if decision.Effect != EffectModify {
		t.Fatalf("expected MODIFY decision, got %s (%s)", decision.Effect, decision.Reason)
	}
	if !decision.RequiredModifications {
		t.Fatal("expected required modifications to be true")
	}
	if decision.ModifyReason != "refund capped by policy" {
		t.Fatalf("modify reason = %q", decision.ModifyReason)
	}
	if got := decision.ModifiedArgs["limit"]; got != 500 {
		t.Fatalf("modified limit = %v, want 500", got)
	}
	if got := decision.ModifiedArgs["isolation"]; got != "docker" {
		t.Fatalf("modified isolation = %v, want docker", got)
	}
}

func TestPipeline_StepUpEffectCarriesAuthorityMetadata(t *testing.T) {
	yamlPolicy := `
faramesh-version: "1.0"
agent-id: "stepup-agent"
rules:
  - id: "high-value-refund"
    match:
      tool: "stripe/refund"
    effect: step_up
    step_up_level: 2
    step_up_authority: "finance_manager"
    step_up_reason: "manager approval required for refunds above threshold"
default_effect: deny
`

	doc, version, err := policy.LoadBytes([]byte(yamlPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{Engine: policy.NewAtomicEngine(eng), Defers: deferwork.NewWorkflow("")})

	decision := p.Evaluate(CanonicalActionRequest{
		CallID:    "step-up-call",
		AgentID:   "stepup-agent",
		SessionID: "stepup-session",
		ToolID:    "stripe/refund",
		Args:      map[string]any{"amount": 7500},
		Timestamp: time.Now().UTC(),
	})

	if decision.Effect != EffectStepUp {
		t.Fatalf("expected STEP_UP decision, got %s (%s)", decision.Effect, decision.Reason)
	}
	if decision.StepUpToken == "" {
		t.Fatal("expected step-up token to be populated")
	}
	if decision.ElevationLevel != 2 {
		t.Fatalf("elevation level = %d, want 2", decision.ElevationLevel)
	}
	if decision.RequiredAuthority != "finance_manager" {
		t.Fatalf("required authority = %q", decision.RequiredAuthority)
	}
	if decision.StepUpReason != "manager approval required for refunds above threshold" {
		t.Fatalf("step-up reason = %q", decision.StepUpReason)
	}
}

func TestPipelineResumeValidationRequiresSignedApprovalEnvelope(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
rules:
  - id: "defer-dangerous"
    tool: "dangerous/run"
    effect: "defer"
    reason: "human approval required"
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	wf := deferwork.NewWorkflow("")
	key := []byte("approval-secret")
	wf.SetApprovalHMACKey(key)
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   wf,
		HMACKey:  key,
	})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "call-1",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
		Timestamp: time.Now(),
	})
	if first.Effect != EffectDefer {
		t.Fatalf("first effect = %q, want defer", first.Effect)
	}
	if err := wf.Resolve(first.DeferToken, true, "approver-1", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	envelopeJSON, code, reason := p.validateResumeApproval(CanonicalActionRequest{
		CallID:    "call-1-resume",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
	}, p.sessions.Get("agent-a"), version)
	if code != "" || envelopeJSON == "" {
		t.Fatalf("validateResumeApproval() = (%q, %q), want success with envelope", code, reason)
	}

	_, code, reason = p.validateResumeApproval(CanonicalActionRequest{
		CallID:    "call-1-resume",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "staging"},
	}, p.sessions.Get("agent-a"), version)
	if code != reasons.ApprovalDenied || !strings.Contains(reason, "resume args do not match") {
		t.Fatalf("tampered resume = (%q, %q), want approval denied args mismatch", code, reason)
	}
}

func TestPipelineApprovedResumeRejectsCascadeDepthLimit(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
rules:
  - id: "defer-dangerous"
    tool: "dangerous/run"
    effect: "defer"
    reason: "human approval required"
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	wf := deferwork.NewWorkflow("")
	key := []byte("approval-secret")
	wf.SetApprovalHMACKey(key)
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   wf,
		HMACKey:  key,
	})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "cascade-call-1",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
		Timestamp: time.Now(),
	})
	if first.Effect != EffectDefer {
		t.Fatalf("first effect = %q, want defer", first.Effect)
	}
	ctx := wf.Context(first.DeferToken)
	if ctx == nil {
		t.Fatal("expected defer context to be stored")
	}
	ctx.CascadeDepth = 4
	ctx.CascadeReason = "policy_changed"

	if err := wf.Resolve(first.DeferToken, true, "approver-1", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	_, code, reason := p.validateResumeApproval(CanonicalActionRequest{
		CallID:    "cascade-call-1-resume",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
	}, p.sessions.Get("agent-a"), version)
	if code != reasons.CascadeDepthLimit {
		t.Fatalf("cascade resume code = %q, want %q (reason=%q)", code, reasons.CascadeDepthLimit, reason)
	}
}

func TestPipelineApprovedResumePermitsDeferredPolicyAction(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
rules:
  - id: "defer-dangerous"
    tool: "dangerous/run"
    effect: "defer"
    reason: "human approval required"
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	wf := deferwork.NewWorkflow("")
	key := []byte("approval-secret")
	wf.SetApprovalHMACKey(key)
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   wf,
		HMACKey:  key,
	})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "call-approve-1",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
		Timestamp: time.Now(),
	})
	if first.Effect != EffectDefer {
		t.Fatalf("first effect = %q, want defer", first.Effect)
	}
	if err := wf.Resolve(first.DeferToken, true, "approver-1", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	resumed := p.Evaluate(CanonicalActionRequest{
		CallID:    "call-approve-1-resume",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
		Timestamp: time.Now(),
	})
	if resumed.Effect != EffectPermit {
		t.Fatalf("resume effect = %q, want permit", resumed.Effect)
	}
	if resumed.ReasonCode != reasons.ApprovalGranted {
		t.Fatalf("resume reason code = %q, want %q", resumed.ReasonCode, reasons.ApprovalGranted)
	}
	if strings.TrimSpace(resumed.ApprovalEnvelopeJSON) == "" {
		t.Fatal("expected approval envelope JSON on resumed decision")
	}
}

func TestPipelineApprovedResumePermitsRoutingDeferredInvocation(t *testing.T) {
	policyYAML := `
faramesh-version: "1.0"
agent-id: "orch-1"
default_effect: deny
orchestrator_manifest:
  agent_id: "orch-1"
  undeclared_invocation_policy: deny
  permitted_invocations:
    - agent_id: "worker-b"
      max_invocations_per_session: 10
      requires_prior_approval: true
delegation_policies:
  - target_agent: "worker-b"
    scope: "safe/*"
    ttl: "1h"
    ceiling: "approval"
rules:
  - id: "allow-invoke"
    match:
      tool: "multiagent/invoke_agent/*"
      when: "true"
    effect: permit
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	wf := deferwork.NewWorkflow("")
	key := []byte("approval-secret")
	wf.SetApprovalHMACKey(key)
	p := NewPipeline(Config{
		Engine:          policy.NewAtomicEngine(eng),
		Sessions:        session.NewManager(),
		Defers:          wf,
		HMACKey:         key,
		RoutingGovernor: multiagent.NewRoutingGovernor(),
	})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "route-approve-1",
		AgentID:   "orch-1",
		SessionID: "sess-1",
		ToolID:    "multiagent/invoke_agent/_execute_tool_sync",
		Args: map[string]any{
			"input": map[string]any{
				"target_agent_id":  "worker-b",
				"delegation_scope": "safe/read",
				"delegation_ttl":   "30m",
			},
		},
		Timestamp: time.Now(),
	})
	if first.Effect != EffectDefer {
		t.Fatalf("first effect = %q, want defer", first.Effect)
	}
	if err := wf.Resolve(first.DeferToken, true, "approver-1", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	resumed := p.Evaluate(CanonicalActionRequest{
		CallID:    "route-approve-1-resume",
		AgentID:   "orch-1",
		SessionID: "sess-1",
		ToolID:    "multiagent/invoke_agent/_execute_tool_sync",
		Args: map[string]any{
			"input": map[string]any{
				"target_agent_id":  "worker-b",
				"delegation_scope": "safe/read",
				"delegation_ttl":   "30m",
			},
		},
		Timestamp: time.Now(),
	})
	if resumed.Effect != EffectPermit {
		t.Fatalf("resume effect = %q, want permit", resumed.Effect)
	}
	if resumed.ReasonCode != reasons.RulePermit {
		t.Fatalf("resume reason code = %q, want %q", resumed.ReasonCode, reasons.RulePermit)
	}
	if strings.TrimSpace(resumed.ApprovalEnvelopeJSON) == "" {
		t.Fatal("expected approval envelope JSON on routing resumed decision")
	}
}

func TestPipelineApprovedResumePersistsApprovalEnvelopeToSQLite(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
rules:
  - id: "defer-dangerous"
    tool: "dangerous/run"
    effect: "defer"
    reason: "human approval required"
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	dir := t.TempDir()
	store, err := dpr.OpenStore(filepath.Join(dir, "faramesh.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	wal, err := dpr.OpenWAL(filepath.Join(dir, "faramesh.wal"))
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer func() { _ = wal.Close() }()
	queue := jobs.NewInprocDPRQueue(store, jobs.InprocDPRQueueConfig{})
	defer func() { _ = queue.Close() }()

	wf := deferwork.NewWorkflow("")
	key := []byte("approval-secret")
	wf.SetApprovalHMACKey(key)
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		WAL:      wal,
		Store:    store,
		DPRQueue: queue,
		Sessions: session.NewManager(),
		Defers:   wf,
		HMACKey:  key,
	})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "call-persist-1",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
		Timestamp: time.Now(),
	})
	if first.Effect != EffectDefer {
		t.Fatalf("first effect = %q, want defer", first.Effect)
	}
	if err := wf.Resolve(first.DeferToken, true, "approver-1", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	resumed := p.Evaluate(CanonicalActionRequest{
		CallID:    "call-persist-1-resume",
		AgentID:   "agent-a",
		SessionID: "sess-1",
		ToolID:    "dangerous/run",
		Args:      map[string]any{"target": "prod"},
		Timestamp: time.Now(),
	})
	if resumed.Effect != EffectPermit {
		t.Fatalf("resume effect = %q, want permit", resumed.Effect)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		recs, err := store.RecentByAgent("agent-a", 10)
		if err != nil {
			if strings.Contains(err.Error(), "SQLITE_BUSY") || strings.Contains(err.Error(), "database is locked") {
				if time.Now().After(deadline) {
					t.Fatalf("RecentByAgent() remained busy: %v", err)
				}
				time.Sleep(25 * time.Millisecond)
				continue
			}
			t.Fatalf("RecentByAgent() error = %v", err)
		}
		for _, rec := range recs {
			if rec.ToolID == "dangerous/run" && rec.Effect == "PERMIT" && strings.TrimSpace(rec.ApprovalEnvelope) != "" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for resumed permit DPR with approval envelope")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPipelineParallelBudgetCancelsAgentAfterPerAgentExceed(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
parallel_budget:
  orchestration_id: "orch-1"
  agents: ["agent-a"]
  aggregate_max_cost_usd: 2.0
  per_agent_max_cost_usd: 1.0
  on_aggregate_exceed: "cancel_remaining"
tools:
  expensive/tool:
    cost_usd: 0.6
rules:
  - id: "permit-expensive"
    tool: "expensive/tool"
    effect: "permit"
`
	p := buildPipelineFromYAML(t, policyYAML)

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-a-1",
		AgentID:   "agent-a",
		SessionID: "parallel-sess",
		ToolID:    "expensive/tool",
		Timestamp: time.Now(),
	})
	if first.Effect != EffectPermit {
		t.Fatalf("first effect = %q, want permit", first.Effect)
	}

	second := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-a-2",
		AgentID:   "agent-a",
		SessionID: "parallel-sess",
		ToolID:    "expensive/tool",
		Timestamp: time.Now(),
	})
	if second.Effect != EffectPermit {
		t.Fatalf("second effect = %q, want permit before per-agent cancellation applies", second.Effect)
	}

	third := p.Evaluate(CanonicalActionRequest{
		CallID:    "budget-a-3",
		AgentID:   "agent-a",
		SessionID: "parallel-sess",
		ToolID:    "expensive/tool",
		Timestamp: time.Now(),
	})
	if third.Effect != EffectDeny {
		t.Fatalf("third effect = %q, want deny after per-agent exceed", third.Effect)
	}
	if third.ReasonCode != reasons.AggregateBudgetExceeded {
		t.Fatalf("third reason code = %q, want %q", third.ReasonCode, reasons.AggregateBudgetExceeded)
	}
}

func TestPipelineShadowModeOverridesDenyToShadowPermit(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
rules:
  - id: "deny-shell"
    tool: "shell/exec"
    effect: "deny"
    reason: "blocked"
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{
		Engine:      policy.NewAtomicEngine(eng),
		Sessions:    session.NewManager(),
		Defers:      deferwork.NewWorkflow(""),
		RuntimeMode: RuntimeModeShadow,
	})

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "shadow-deny",
		AgentID:   "agent-a",
		SessionID: "sess-shadow",
		ToolID:    "shell/exec",
		Timestamp: time.Now(),
	})
	if d.Effect != EffectShadowPermit {
		t.Fatalf("effect = %q, want shadow_permit", d.Effect)
	}
	if d.ShadowActualOutcome != EffectDeny {
		t.Fatalf("shadow actual outcome = %q, want deny", d.ShadowActualOutcome)
	}
	if d.ReasonCode != reasons.ShadowDeny {
		t.Fatalf("reason code = %q, want %q", d.ReasonCode, reasons.ShadowDeny)
	}
}

func TestPipelineAuditModeSkipsPolicyEvaluation(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
rules:
  - id: "deny-shell"
    tool: "shell/exec"
    effect: "deny"
    reason: "blocked"
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{
		Engine:      policy.NewAtomicEngine(eng),
		Sessions:    session.NewManager(),
		Defers:      deferwork.NewWorkflow(""),
		RuntimeMode: RuntimeModeAudit,
	})

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "audit-shell",
		AgentID:   "agent-a",
		SessionID: "sess-audit",
		ToolID:    "shell/exec",
		Timestamp: time.Now(),
	})
	if d.Effect != EffectShadowPermit {
		t.Fatalf("effect = %q, want shadow_permit", d.Effect)
	}
	if d.ShadowActualOutcome != EffectPermit {
		t.Fatalf("shadow actual outcome = %q, want permit passthrough", d.ShadowActualOutcome)
	}
	if !strings.Contains(d.Reason, "audit mode passthrough") {
		t.Fatalf("reason = %q, want audit passthrough message", d.Reason)
	}
}

func TestPipelineBootstrapEnforcerDeniesFirstNetworkTool(t *testing.T) {
	policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: permit
rules:
  - id: "allow-http"
    tool: "http/request"
    effect: "permit"
`
	doc, version, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{
		Engine:    policy.NewAtomicEngine(eng),
		Sessions:  session.NewManager(),
		Defers:    deferwork.NewWorkflow(""),
		Bootstrap: NewBootstrapEnforcer(true),
	})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:    "bootstrap-1",
		AgentID:   "agent-a",
		SessionID: "sess-bootstrap",
		ToolID:    "http/request",
		Timestamp: time.Now(),
	})
	if first.Effect != EffectDeny {
		t.Fatalf("first effect = %q, want deny", first.Effect)
	}
	if first.ReasonCode != reasons.GovernanceBootstrapRequired {
		t.Fatalf("first reason code = %q, want %q", first.ReasonCode, reasons.GovernanceBootstrapRequired)
	}

	second := p.Evaluate(CanonicalActionRequest{
		CallID:    "bootstrap-2",
		AgentID:   "agent-a",
		SessionID: "sess-bootstrap",
		ToolID:    "http/request",
		Timestamp: time.Now(),
	})
	if second.Effect != EffectPermit {
		t.Fatalf("second effect = %q, want permit after governance bootstrap mark", second.Effect)
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
