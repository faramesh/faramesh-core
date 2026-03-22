package core

import (
	"fmt"
	"sync"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const p5HookPolicy = `
faramesh-version: "1.0"
agent-id: "p5-hook-agent"

rules:
  - id: permit-read
    match:
      tool: "safe/read"
    effect: permit
    reason: "safe permit"

  - id: deny-danger
    match:
      tool: "danger/run"
    effect: deny
    reason: "danger denied"
    reason_code: RULE_DENY

default_effect: deny
`

func buildP5HookPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(p5HookPolicy))
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

type captureHooks struct {
	mu       sync.Mutex
	accesses []observe.AccessEvent
	rules    []observe.RuleObservation
}

func (c *captureHooks) RecordAccess(evt observe.AccessEvent) error {
	c.mu.Lock()
	c.accesses = append(c.accesses, evt)
	c.mu.Unlock()
	return nil
}

func (c *captureHooks) ObserveRule(obs observe.RuleObservation) error {
	c.mu.Lock()
	c.rules = append(c.rules, obs)
	c.mu.Unlock()
	return nil
}

func TestP5PermitRecordsCrossSessionAccessAndRuleObservation(t *testing.T) {
	p := buildP5HookPipeline(t)
	h := &captureHooks{}
	observe.Default.SetCrossSessionTracker(h)
	observe.Default.SetPIEAnalyzer(h)
	defer func() {
		observe.Default.SetCrossSessionTracker(nil)
		observe.Default.SetPIEAnalyzer(nil)
	}()

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "p5-permit",
		AgentID:   "agent-p5",
		SessionID: "sess-p5",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now(),
		Principal: &principal.Identity{ID: "principal-p5", Verified: true, Method: "spiffe"},
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s (%s)", d.Effect, d.Reason)
	}
	if d.DPRRecordID == "" {
		t.Fatal("expected DPR record id on permit decision")
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		accesses := len(h.accesses)
		rules := len(h.rules)
		h.mu.Unlock()
		if accesses >= 1 && rules >= 1 {
			h.mu.Lock()
			a := h.accesses[0]
			h.mu.Unlock()
			if a.PrincipalID != "principal-p5" {
				t.Fatalf("expected PrincipalID on access event, got %q", a.PrincipalID)
			}
			if a.DPRID != d.DPRRecordID {
				t.Fatalf("expected DPRID %q on access event, got %q", d.DPRRecordID, a.DPRID)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected permit hooks to be called")
}

type failingHooks struct{}

func (f failingHooks) RecordAccess(observe.AccessEvent) error { return fmt.Errorf("boom-access") }
func (f failingHooks) ObserveRule(observe.RuleObservation) error {
	return fmt.Errorf("boom-rule")
}

func TestP5HooksFailOpenDoNotBreakDecisions(t *testing.T) {
	p := buildP5HookPipeline(t)
	observe.Default.SetCrossSessionTracker(failingHooks{})
	observe.Default.SetPIEAnalyzer(failingHooks{})
	defer func() {
		observe.Default.SetCrossSessionTracker(nil)
		observe.Default.SetPIEAnalyzer(nil)
	}()

	permit := p.Evaluate(CanonicalActionRequest{
		CallID:    "p5-fail-open-permit",
		AgentID:   "agent-p5",
		SessionID: "sess-p5",
		ToolID:    "safe/read",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if permit.Effect != EffectPermit {
		t.Fatalf("permit decision should remain unchanged, got %s (%s)", permit.Effect, permit.Reason)
	}

	deny := p.Evaluate(CanonicalActionRequest{
		CallID:    "p5-fail-open-deny",
		AgentID:   "agent-p5",
		SessionID: "sess-p5",
		ToolID:    "danger/run",
		Args:      map[string]any{},
		Timestamp: time.Now(),
	})
	if deny.Effect != EffectDeny {
		t.Fatalf("deny decision should remain unchanged, got %s (%s)", deny.Effect, deny.Reason)
	}
}
