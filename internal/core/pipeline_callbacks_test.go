package core

import (
	"sync"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/callbacks"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const callbackPolicy = `
faramesh-version: "1.0"
agent-id: "callback-agent"

rules:
  - id: permit-any
    match:
      tool: "safe/read"
    effect: permit
    reason: "allowed"

default_effect: deny
`

const callbackDeferPolicy = `
faramesh-version: "1.0"
agent-id: "callback-agent"

rules:
  - id: defer-refund
    match:
      tool: "payment/refund"
    effect: defer
    reason: "manual approval required"

default_effect: deny
`

type captureDecisionCallback struct {
	mu      sync.Mutex
	payload callbacks.OnDecisionPayload
	called  bool
}

func (c *captureDecisionCallback) FireOnDecision(p callbacks.OnDecisionPayload) error {
	c.mu.Lock()
	c.payload = p
	c.called = true
	c.mu.Unlock()
	return nil
}

func buildCallbackPipeline(t *testing.T, cb callbacks.Dispatcher) *Pipeline {
	return buildCallbackPipelineWithPolicy(t, cb, callbackPolicy)
}

func buildCallbackPipelineWithPolicy(t *testing.T, cb callbacks.Dispatcher, policyDoc string) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(policyDoc))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:    policy.NewAtomicEngine(eng),
		Sessions:  session.NewManager(),
		Defers:    deferwork.NewWorkflow(""),
		Callbacks: cb,
	})
}

func TestPipelineOnDecisionCallbackFiresWithContext(t *testing.T) {
	cb := &captureDecisionCallback{}
	p := buildCallbackPipeline(t, cb)

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "cb-fire-1",
		AgentID:   "agent-cb",
		SessionID: "session-cb",
		ToolID:    "safe/read",
		Args:      map[string]any{"k": "v"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit decision, got %s (%s)", d.Effect, d.Reason)
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if !cb.called {
		t.Fatalf("expected on_decision callback to fire")
	}
	if cb.payload.AgentID != "agent-cb" {
		t.Fatalf("expected callback agent_id=agent-cb, got %q", cb.payload.AgentID)
	}
	if cb.payload.ToolID != "safe/read" {
		t.Fatalf("expected callback tool_id=safe/read, got %q", cb.payload.ToolID)
	}
	if cb.payload.Effect != "PERMIT" {
		t.Fatalf("expected callback effect=PERMIT, got %q", cb.payload.Effect)
	}
	if cb.payload.ReasonCode == "" {
		t.Fatalf("expected callback reason_code to be populated")
	}
	if cb.payload.RecordID == "" {
		t.Fatalf("expected callback record_id to be populated")
	}
}

func TestPipelineOnDecisionCallbackFailureDeniesPermit(t *testing.T) {
	// Unreachable callback URL must fail-closed for permit path.
	type callbackConfig struct {
		OnDecision struct {
			URL       string
			TimeoutMS int
		}
		Workers int
	}
	var cfg callbackConfig
	cfg.OnDecision.URL = "http://127.0.0.1:1/callback"
	cfg.OnDecision.TimeoutMS = 10
	cfg.Workers = 1

	cm := callbacks.NewFromPolicyCallbacks(cfg)
	p := buildCallbackPipeline(t, cm)

	start := time.Now()
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "cb-fail-open-1",
		AgentID:   "agent-cb",
		SessionID: "session-cb",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	elapsed := time.Since(start)
	if d.Effect != EffectDeny {
		t.Fatalf("callback failure must deny decision, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != "CALLBACK_ERROR" {
		t.Fatalf("expected reason code CALLBACK_ERROR, got %q", d.ReasonCode)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("strict callback dispatch exceeded timeout budget, elapsed=%s", elapsed)
	}
}

func TestPipelineOnDecisionCallbackFailureKeepsDenyFailClosed(t *testing.T) {
	type callbackConfig struct {
		OnDecision struct {
			URL       string
			TimeoutMS int
		}
		Workers int
	}
	var cfg callbackConfig
	cfg.OnDecision.URL = "http://127.0.0.1:1/callback"
	cfg.OnDecision.TimeoutMS = 10
	cfg.Workers = 1

	cm := callbacks.NewFromPolicyCallbacks(cfg)
	p := buildCallbackPipeline(t, cm)

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "cb-fail-deny-1",
		AgentID:   "agent-cb",
		SessionID: "session-cb",
		ToolID:    "unsafe/write",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != "CALLBACK_ERROR" {
		t.Fatalf("expected reason code CALLBACK_ERROR, got %q", d.ReasonCode)
	}
}

func TestPipelineOnDecisionCallbackFailureConvertsDeferToDeny(t *testing.T) {
	type callbackConfig struct {
		OnDecision struct {
			URL       string
			TimeoutMS int
		}
		Workers int
	}
	var cfg callbackConfig
	cfg.OnDecision.URL = "http://127.0.0.1:1/callback"
	cfg.OnDecision.TimeoutMS = 10
	cfg.Workers = 1

	cm := callbacks.NewFromPolicyCallbacks(cfg)
	p := buildCallbackPipelineWithPolicy(t, cm, callbackDeferPolicy)

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "cb-fail-defer-1",
		AgentID:   "agent-cb",
		SessionID: "session-cb",
		ToolID:    "payment/refund",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected callback failure to deny deferred action, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != "CALLBACK_ERROR" {
		t.Fatalf("expected reason code CALLBACK_ERROR, got %q", d.ReasonCode)
	}
}
