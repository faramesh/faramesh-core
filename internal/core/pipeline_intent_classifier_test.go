package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

type staticIntentClassifier struct {
	class string
	ttl   time.Duration
	calls atomic.Int64
}

func (s *staticIntentClassifier) Classify(_ context.Context, _ CanonicalActionRequest, _ Decision) (IntentClassification, error) {
	s.calls.Add(1)
	return IntentClassification{Class: s.class, TTL: s.ttl}, nil
}

func buildSessionIntentPipelineWithClassifier(t *testing.T, classifier IntentClassifier) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(sessionIntentPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:           policy.NewAtomicEngine(eng),
		Sessions:         session.NewManager(),
		SessionGovernor:  session.NewGovernor(),
		Defers:           deferwork.NewWorkflow(""),
		IntentClassifier: classifier,
	})
}

func TestAsyncIntentClassifierWritesSessionIntentClass(t *testing.T) {
	classifier := &staticIntentClassifier{class: "high_risk_intent", ttl: 5 * time.Minute}
	p := buildSessionIntentPipelineWithClassifier(t, classifier)

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "intent-classifier-source",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "notes/create",
		Args:      map[string]any{"text": "please draft outbound update"},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit for source tool, got %s (%s)", d.Effect, d.Reason)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := p.SessionManager().Get("agent-1").IntentClass(time.Now()); got == "high_risk_intent" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := p.SessionManager().Get("agent-1").IntentClass(time.Now()); got != "high_risk_intent" {
		t.Fatalf("expected async classifier write to set intent class, got %q", got)
	}
	if classifier.calls.Load() == 0 {
		t.Fatal("expected classifier to be invoked")
	}

	followUp := p.Evaluate(CanonicalActionRequest{
		CallID:    "intent-classifier-follow-up",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "admin/delete_customer",
		Args:      map[string]any{"id": "cust-123"},
		Timestamp: time.Now(),
	})
	if followUp.Effect != EffectDefer {
		t.Fatalf("expected defer after async high-risk classification, got %s (%s)", followUp.Effect, followUp.Reason)
	}
}

func TestAsyncIntentClassifierSkipsSessionWriteTools(t *testing.T) {
	classifier := &staticIntentClassifier{class: "high_risk_intent", ttl: 5 * time.Minute}
	p := buildSessionIntentPipelineWithClassifier(t, classifier)

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "intent-classifier-session-write",
		AgentID:   "agent-1",
		SessionID: "sess-1",
		ToolID:    "session/write",
		Args: map[string]any{
			"key":   "agent-1/profile/theme",
			"value": "dark",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit for session write, got %s (%s)", d.Effect, d.Reason)
	}

	time.Sleep(80 * time.Millisecond)
	if classifier.calls.Load() != 0 {
		t.Fatalf("expected classifier not to run for session/write, calls=%d", classifier.calls.Load())
	}
}
