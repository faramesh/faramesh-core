package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestEvaluateUnmatchedUsesDefaultEffectReasonCode(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "permit",
		Rules: []Rule{
			{
				ID: "only-transfer",
				Match: Match{
					Tool: "transfer",
					When: "true",
				},
				Effect: "deny",
			},
		},
	}
	e, err := NewEngine(doc, "v-test")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	res := e.Evaluate("other-tool", EvalContext{})
	if res.Effect != "permit" {
		t.Fatalf("expected default permit effect, got %q", res.Effect)
	}
	if res.ReasonCode != "UNMATCHED_PERMIT" {
		t.Fatalf("expected UNMATCHED_PERMIT, got %q", res.ReasonCode)
	}

	resTimeout := e.EvaluateWithTimeout(context.Background(), "other-tool", EvalContext{})
	if resTimeout.Effect != "permit" {
		t.Fatalf("timeout path: expected default permit effect, got %q", resTimeout.Effect)
	}
	if resTimeout.ReasonCode != "UNMATCHED_PERMIT" {
		t.Fatalf("timeout path: expected UNMATCHED_PERMIT, got %q", resTimeout.ReasonCode)
	}
}

func TestEvaluateRuntimeExpressionErrorReturnsExplicitDeny(t *testing.T) {
	opName := fmt.Sprintf("test_runtime_error_%d", time.Now().UnixNano())
	if err := DefaultOperatorRegistry().Register(OperatorMeta{
		Name:          opName,
		Deterministic: true,
		ReturnType:    "bool",
	}, func(args ...any) (any, error) {
		return nil, fmt.Errorf("boom")
	}); err != nil {
		t.Fatalf("register operator: %v", err)
	}

	doc := &Doc{
		DefaultEffect: "permit",
		Rules: []Rule{
			{
				ID: "runtime-error-rule",
				Match: Match{
					Tool: "*",
					When: opName + "()",
				},
				Effect: "permit",
			},
		},
	}
	e, err := NewEngine(doc, "v-test")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	res := e.Evaluate("x", EvalContext{})
	if res.Effect != "deny" {
		t.Fatalf("expected explicit deny on runtime error, got %q", res.Effect)
	}
	if res.ReasonCode != "EXPR_RUNTIME_ERROR" {
		t.Fatalf("expected EXPR_RUNTIME_ERROR, got %q", res.ReasonCode)
	}
}

func TestEvaluateWithTimeoutCancellationReturnsExplicitDeny(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "permit",
		Rules: []Rule{
			{
				ID: "any-rule",
				Match: Match{
					Tool: "*",
					When: "true",
				},
				Effect: "permit",
			},
		},
	}
	e, err := NewEngine(doc, "v-test")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := e.EvaluateWithTimeout(ctx, "x", EvalContext{})
	if res.Effect != "deny" {
		t.Fatalf("expected explicit deny on timeout, got %q", res.Effect)
	}
	if res.ReasonCode != "GOVERNANCE_TIMEOUT" {
		t.Fatalf("expected GOVERNANCE_TIMEOUT, got %q", res.ReasonCode)
	}
}
