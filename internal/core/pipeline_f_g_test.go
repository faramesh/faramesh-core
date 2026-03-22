package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/phases"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const fgPolicy = `
faramesh-version: "1.0"
agent-id: "fg-test-agent"

rules:
  - id: deny-dangerous-tools
    match:
      tool: "danger/*"
    effect: deny
    reason: "dangerous tool denied"
    reason_code: RULE_DENY

  - id: defer-on-deny-burst
    match:
      tool: "*"
      when: "deny_count_within(120) >= 2"
    effect: defer
    reason: "too many denies in short window"
    reason_code: SESSION_ATTEMPT_LIMIT

  - id: deny-large-recipient-array
    match:
      tool: "email/send"
      when: "args_array_len('recipients') > 3"
    effect: deny
    reason: "too many recipients"
    reason_code: ARRAY_CARDINALITY_EXCEEDED

  - id: deny-external-domain-recipient
    match:
      tool: "email/send"
      when: "args_array_any_match('recipients', '*@external.com')"
    effect: deny
    reason: "external recipient denied"
    reason_code: RULE_DENY

  - id: permit-default
    match:
      tool: "*"
    effect: permit
    reason: "default permit"

default_effect: deny
`

func buildFGPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(fgPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func fgReq(agent, tool string, args map[string]any) CanonicalActionRequest {
	return CanonicalActionRequest{
		CallID:    "fg-" + tool + "-" + time.Now().Format("150405.000000"),
		AgentID:   agent,
		SessionID: "fg-sess",
		ToolID:    tool,
		Args:      args,
		Timestamp: time.Now(),
	}
}

func TestCategoryFDenyEscalationControl(t *testing.T) {
	p := buildFGPipeline(t)
	const agent = "agent-f"

	d1 := p.Evaluate(fgReq(agent, "danger/one", nil))
	if d1.Effect != EffectDeny {
		t.Fatalf("first dangerous call: want DENY, got %s", d1.Effect)
	}
	d2 := p.Evaluate(fgReq(agent, "danger/two", nil))
	if d2.Effect != EffectDeny {
		t.Fatalf("second dangerous call: want DENY, got %s", d2.Effect)
	}

	d3 := p.Evaluate(fgReq(agent, "safe/read", nil))
	if d3.Effect != EffectDefer {
		t.Fatalf("deny burst escalation: want DEFER, got %s (%s)", d3.Effect, d3.Reason)
	}
}

func TestCategoryGArrayCardinalityControl(t *testing.T) {
	p := buildFGPipeline(t)
	const agent = "agent-g-cardinality"

	d := p.Evaluate(fgReq(agent, "email/send", map[string]any{
		"recipients": []any{"a@company.com", "b@company.com", "c@company.com", "d@company.com"},
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("array cardinality guard: want DENY, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestCategoryGArrayPatternControl(t *testing.T) {
	p := buildFGPipeline(t)
	const agent = "agent-g-pattern"

	d := p.Evaluate(fgReq(agent, "email/send", map[string]any{
		"recipients": []any{"ops@company.com", "vendor@external.com"},
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("array pattern guard: want DENY, got %s (%s)", d.Effect, d.Reason)
	}
}

const isolationPolicy = `
faramesh-version: "1.0"
agent-id: "iso-agent"

execution_isolation:
  enabled: true
  default_backend: "firecracker"
  tool_isolation_policy:
    "danger/*": "required"
    "safe/*": "optional"

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "permit"

default_effect: deny
`

func buildIsolationPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(isolationPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func TestExecutionIsolationRequiredDeniedWhenMissing(t *testing.T) {
	p := buildIsolationPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "iso-missing",
		AgentID:   "iso-agent",
		SessionID: "iso-sess",
		ToolID:    "danger/run",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("missing isolation: want DENY, got %s", d.Effect)
	}
}

func TestExecutionIsolationRequiredPermitsWhenMet(t *testing.T) {
	p := buildIsolationPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:               "iso-met",
		AgentID:              "iso-agent",
		SessionID:            "iso-sess",
		ToolID:               "danger/run",
		Args:                 map[string]any{},
		ExecutionEnvironment: "firecracker",
		Timestamp:            time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("required isolation met: want PERMIT, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestExecutionIsolationOptionalDoesNotDeny(t *testing.T) {
	p := buildIsolationPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "iso-optional",
		AgentID:   "iso-agent",
		SessionID: "iso-sess",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("optional isolation: want PERMIT, got %s (%s)", d.Effect, d.Reason)
	}
}

const toolSchemaPolicy = `
faramesh-version: "1.0"
agent-id: "schema-agent"

tool_schemas:
  payment/charge:
    name: "charge"
    version: "v1"
    parameters:
      amount:
        type: number
        required: true
      currency:
        type: string
        required: true

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit

default_effect: deny
`

func TestToolSchemaValidationEnforced(t *testing.T) {
	doc, ver, err := policy.LoadBytes([]byte(toolSchemaPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	deny := p.Evaluate(CanonicalActionRequest{
		CallID:    "schema-missing",
		AgentID:   "schema-agent",
		SessionID: "schema-sess",
		ToolID:    "payment/charge",
		Args:      map[string]any{"amount": 99.5},
		Timestamp: time.Now(),
	})
	if deny.Effect != EffectDeny {
		t.Fatalf("expected schema deny, got %s (%s)", deny.Effect, deny.Reason)
	}

	permit := p.Evaluate(CanonicalActionRequest{
		CallID:    "schema-ok",
		AgentID:   "schema-agent",
		SessionID: "schema-sess",
		ToolID:    "payment/charge",
		Args:      map[string]any{"amount": 99.5, "currency": "USD"},
		Timestamp: time.Now(),
	})
	if permit.Effect != EffectPermit {
		t.Fatalf("expected schema permit, got %s (%s)", permit.Effect, permit.Reason)
	}
}

const reloadPolicyV1 = `
faramesh-version: "1.0"
agent-id: "reload-agent"

tool_schemas:
  tool/op:
    name: "op-v1"
    version: "v1"
    parameters:
      a:
        type: string
        required: true

post_rules:
  - id: redact-v1
    match:
      tool: "tool/*"
    scan:
      - pattern: "AAA"
        action: redact
        replacement: "[V1]"

rules:
  - id: permit-op
    match:
      tool: "tool/op"
    effect: permit

default_effect: deny
`

const reloadPolicyV2 = `
faramesh-version: "1.0"
agent-id: "reload-agent"

tool_schemas:
  tool/op:
    name: "op-v2"
    version: "v2"
    parameters:
      b:
        type: string
        required: true

post_rules:
  - id: redact-v2
    match:
      tool: "tool/*"
    scan:
      - pattern: "BBB"
        action: redact
        replacement: "[V2]"

rules:
  - id: permit-op
    match:
      tool: "tool/op"
    effect: permit

default_effect: deny
`

func compilePolicyEngine(t *testing.T, src, version string) (*policy.Doc, *policy.Engine) {
	t.Helper()
	doc, _, err := policy.LoadBytes([]byte(src))
	if err != nil {
		t.Fatalf("load policy %s: %v", version, err)
	}
	eng, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy %s: %v", version, err)
	}
	return doc, eng
}

func TestPolicyReloadGenerationConsistency(t *testing.T) {
	docV1, engV1 := compilePolicyEngine(t, reloadPolicyV1, "v1")
	docV2, engV2 := compilePolicyEngine(t, reloadPolicyV2, "v2")

	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engV1),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	var inconsistent atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			d := p.Evaluate(CanonicalActionRequest{
				CallID:    fmt.Sprintf("reload-eval-%d", i),
				AgentID:   "reload-agent",
				SessionID: "reload-sess",
				ToolID:    "tool/op",
				Args:      map[string]any{"a": "ok"},
				Timestamp: time.Now(),
			})
			// Under v2, schema requires "b", so "a"-only args must never be permitted.
			if d.PolicyVersion == "v2" && d.Effect == EffectPermit {
				inconsistent.Store(true)
				return
			}
		}
	}()

	for i := 0; i < 300; i++ {
		if err := p.ApplyPolicyBundle(docV2, engV2); err != nil {
			t.Fatalf("apply v2 bundle: %v", err)
		}
		if err := p.ApplyPolicyBundle(docV1, engV1); err != nil {
			t.Fatalf("apply v1 bundle: %v", err)
		}
	}
	wg.Wait()
	if inconsistent.Load() {
		t.Fatalf("observed mixed-generation decision (v2 engine with v1 schema)")
	}

	if err := p.ApplyPolicyBundle(docV2, engV2); err != nil {
		t.Fatalf("final apply v2 bundle: %v", err)
	}
	scan := p.ScanOutput("tool/op", "AAA BBB")
	if scan.Outcome != "REDACTED" || scan.Output != "AAA [V2]" {
		t.Fatalf("scan output should come from v2 scanner, got outcome=%s output=%q", scan.Outcome, scan.Output)
	}
}

const subPolicyEnforcementPolicy = `
faramesh-version: "1.0"
agent-id: "subpolicy-agent"

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "permit by base policy"

default_effect: deny
`

const workflowStepScopedPolicy = `
faramesh-version: "1.0"
agent-id: "workflow-step-agent"

phases:
  init:
    tools:
      - "safe/*"
      - "step:draft:safe/read"
      - "step:execute:safe/write"

rules:
  - id: permit-safe
    match:
      tool: "safe/*"
    effect: permit
    reason: "safe permit"

default_effect: deny
`

func buildWorkflowStepPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(workflowStepScopedPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func buildSubPolicyPipeline(t *testing.T, spm *multiagent.SubPolicyManager) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(subPolicyEnforcementPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:      policy.NewAtomicEngine(eng),
		Sessions:    session.NewManager(),
		Defers:      deferwork.NewWorkflow(""),
		SubPolicies: spm,
	})
}

func TestInvocationSubPolicyAllowsWhenIntersecting(t *testing.T) {
	spm := multiagent.NewSubPolicyManager()
	spm.AttachPolicy(multiagent.SubPolicy{
		InvocationID: "inv-allow",
		AllowedTools: []string{"safe/*"},
	})
	p := buildSubPolicyPipeline(t, spm)

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "subpolicy-allow",
		AgentID:   "agent-subpolicy",
		SessionID: "sess-subpolicy",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Invocation: &InvocationContext{
			ID: "inv-allow",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("sub-policy allow path: want PERMIT, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestInvocationSubPolicyDeniesEvenWhenBasePolicyPermits(t *testing.T) {
	spm := multiagent.NewSubPolicyManager()
	spm.AttachPolicy(multiagent.SubPolicy{
		InvocationID: "inv-deny",
		AllowedTools: []string{"safe/*"},
	})
	p := buildSubPolicyPipeline(t, spm)

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "subpolicy-deny",
		AgentID:   "agent-subpolicy",
		SessionID: "sess-subpolicy",
		ToolID:    "danger/run",
		Args:      map[string]any{},
		Invocation: &InvocationContext{
			ID: "inv-deny",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("sub-policy deny path: want DENY, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.RoutingInvocationSubPolicyDenied {
		t.Fatalf("sub-policy deny reason code: want %s, got %s", reasons.RoutingInvocationSubPolicyDenied, d.ReasonCode)
	}
}

func TestInvocationNoSubPolicyKeepsBaseBehavior(t *testing.T) {
	p := buildSubPolicyPipeline(t, multiagent.NewSubPolicyManager())

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "subpolicy-none",
		AgentID:   "agent-subpolicy",
		SessionID: "sess-subpolicy",
		ToolID:    "danger/run",
		Args:      map[string]any{},
		Invocation: &InvocationContext{
			ID: "inv-missing",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("no sub-policy path should keep base policy permit, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestWorkflowStepAllowsToolWhenInStepAllowlist(t *testing.T) {
	p := buildWorkflowStepPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:       "workflow-step-allow",
		AgentID:      "workflow-step-agent",
		SessionID:    "workflow-step-sess",
		ToolID:       "safe/read",
		Args:         map[string]any{},
		WorkflowStep: "draft",
		Timestamp:    time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("step allowlist should permit safe/read in draft step, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestWorkflowStepDeniesToolOutsideStepAllowlist(t *testing.T) {
	p := buildWorkflowStepPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:       "workflow-step-deny-out",
		AgentID:      "workflow-step-agent",
		SessionID:    "workflow-step-sess",
		ToolID:       "safe/write",
		Args:         map[string]any{},
		WorkflowStep: "draft",
		Timestamp:    time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("step allowlist should deny safe/write in draft step, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.OutOfWorkflowStepToolCall {
		t.Fatalf("want reason code %s, got %s", reasons.OutOfWorkflowStepToolCall, d.ReasonCode)
	}
}

func TestWorkflowStepUnknownStepFailsClosed(t *testing.T) {
	p := buildWorkflowStepPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:       "workflow-step-unknown",
		AgentID:      "workflow-step-agent",
		SessionID:    "workflow-step-sess",
		ToolID:       "safe/read",
		Args:         map[string]any{},
		WorkflowStep: "unknown-step",
		Timestamp:    time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("unknown workflow step should deny, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.UnknownWorkflowStep {
		t.Fatalf("want reason code %s, got %s", reasons.UnknownWorkflowStep, d.ReasonCode)
	}
}

func TestPhaseManagerDelegationPathIsExercised(t *testing.T) {
	doc, ver, err := policy.LoadBytes([]byte(workflowStepScopedPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	// Manager intentionally differs from doc.Phases allowlist. If pipeline uses
	// manager delegation, safe/read is denied even though policy phase tools allow it.
	pm := phases.NewPhaseManager([]phases.Phase{
		{
			ID:                 "init",
			Name:               "init",
			AllowedTools:       []string{"danger/*"},
			AllowedTransitions: []string{"*"},
		},
	})
	p := NewPipeline(Config{
		Engine:       policy.NewAtomicEngine(eng),
		Sessions:     session.NewManager(),
		Defers:       deferwork.NewWorkflow(""),
		PhaseManager: pm,
	})

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "phase-manager-path",
		AgentID:   "phase-manager-agent",
		SessionID: "phase-manager-sess",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("phase manager path should deny out-of-phase tool, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.OutOfPhaseToolCall {
		t.Fatalf("want reason code %s, got %s", reasons.OutOfPhaseToolCall, d.ReasonCode)
	}
}

func TestPhaseCheckFallbackWithoutManagerPreservesBehavior(t *testing.T) {
	p := buildWorkflowStepPipeline(t) // no phase manager configured
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "phase-fallback-path",
		AgentID:   "phase-fallback-agent",
		SessionID: "phase-fallback-sess",
		ToolID:    "danger/run",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("fallback phase check should deny out-of-phase tool, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.OutOfPhaseToolCall {
		t.Fatalf("want reason code %s, got %s", reasons.OutOfPhaseToolCall, d.ReasonCode)
	}
}

const timeoutPolicy = `
faramesh-version: "1.0"
agent-id: "timeout-agent"

tools:
  slow/required:
    reversibility: reversible
    blast_radius: local
    tags:
      - "timeout:required"
      - "timeout:min_ms:200"
      - "timeout:max_ms:5000"

rules:
  - id: permit-all
    match:
      tool: "*"
    effect: permit
    reason: "permit"

default_effect: deny
`

func buildTimeoutPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(timeoutPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func TestCategoryXTimeoutRequiredDenyWhenMissing(t *testing.T) {
	p := buildTimeoutPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "timeout-required-missing",
		AgentID:   "timeout-agent",
		SessionID: "timeout-sess",
		ToolID:    "slow/required",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("missing required timeout should deny, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.ExecutionTimeoutRequired {
		t.Fatalf("want reason code %s, got %s", reasons.ExecutionTimeoutRequired, d.ReasonCode)
	}
}

func TestCategoryXTimeoutBoundsValidation(t *testing.T) {
	p := buildTimeoutPipeline(t)
	invalidGlobal := p.Evaluate(CanonicalActionRequest{
		CallID:             "timeout-invalid-global",
		AgentID:            "timeout-agent",
		SessionID:          "timeout-sess",
		ToolID:             "safe/read",
		Args:               map[string]any{},
		ExecutionTimeoutMS: 10,
		Timestamp:          time.Now(),
	})
	if invalidGlobal.Effect != EffectDeny {
		t.Fatalf("globally invalid timeout should deny, got %s", invalidGlobal.Effect)
	}
	if invalidGlobal.ReasonCode != reasons.ExecutionTimeoutInvalid {
		t.Fatalf("want reason code %s, got %s", reasons.ExecutionTimeoutInvalid, invalidGlobal.ReasonCode)
	}

	invalidPolicy := p.Evaluate(CanonicalActionRequest{
		CallID:             "timeout-invalid-policy",
		AgentID:            "timeout-agent",
		SessionID:          "timeout-sess",
		ToolID:             "slow/required",
		Args:               map[string]any{},
		ExecutionTimeoutMS: 100,
		Timestamp:          time.Now(),
	})
	if invalidPolicy.Effect != EffectDeny {
		t.Fatalf("policy-invalid timeout should deny, got %s", invalidPolicy.Effect)
	}
	if invalidPolicy.ReasonCode != reasons.ExecutionTimeoutPolicyViolation {
		t.Fatalf("want reason code %s, got %s", reasons.ExecutionTimeoutPolicyViolation, invalidPolicy.ReasonCode)
	}
}

func TestCategoryXTimeoutValidAndCapturedInDPR(t *testing.T) {
	p := buildTimeoutPipeline(t)
	req := CanonicalActionRequest{
		CallID:    "timeout-valid-dpr",
		AgentID:   "timeout-agent",
		SessionID: "timeout-sess",
		ToolID:    "slow/required",
		Args: map[string]any{
			"execution_timeout_secs": 1,
		},
		Timestamp: time.Now(),
	}
	d := p.Evaluate(req)
	if d.Effect != EffectPermit {
		t.Fatalf("valid timeout should permit, got %s (%s)", d.Effect, d.Reason)
	}
	rec := p.buildRecord(CanonicalActionRequest{
		CallID:             "timeout-valid-dpr-rec",
		AgentID:            req.AgentID,
		SessionID:          req.SessionID,
		ToolID:             req.ToolID,
		Args:               req.Args,
		ExecutionTimeoutMS: 1000,
		Timestamp:          req.Timestamp,
		InterceptAdapter:   "sdk",
	}, Decision{Effect: EffectPermit, PolicyVersion: "test", ReasonCode: reasons.RulePermit}, nil)
	if rec.ExecutionTimeoutMS != 1000 {
		t.Fatalf("expected DPR execution_timeout_ms=1000, got %d", rec.ExecutionTimeoutMS)
	}
}
