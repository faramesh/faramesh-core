package policy

import (
	"context"
	"fmt"
	"strings"
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
	if res.ReasonCode != "POLICY_EVAL_TIMEOUT" {
		t.Fatalf("expected POLICY_EVAL_TIMEOUT, got %q", res.ReasonCode)
	}
}

func TestNewEngineRejectsInvalidPhaseTransitionCondition(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "deny",
		Phases: map[string]Phase{
			"intake":    {Tools: []string{"safe/read"}},
			"execution": {Tools: []string{"safe/write"}},
		},
		PhaseTransitions: []PhaseTransition{
			{
				From:       "intake",
				To:         "execution",
				Conditions: "mystery_symbol > 0",
				Effect:     "permit_transition",
			},
		},
	}

	_, err := NewEngine(doc, "v-test")
	if err == nil {
		t.Fatal("expected transition condition compile error")
	}
	if got := err.Error(); !strings.Contains(got, "phase_transition") {
		t.Fatalf("expected phase_transition context in error, got: %v", err)
	}
}

func TestEvaluatePhaseTransitionMatchesCondition(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "deny",
		Phases: map[string]Phase{
			"intake":    {Tools: []string{"safe/read"}},
			"execution": {Tools: []string{"safe/write"}},
		},
		PhaseTransitions: []PhaseTransition{
			{
				From:       "intake",
				To:         "execution",
				Conditions: "args.promote == true",
				Effect:     "permit_transition",
				Reason:     "ready to execute",
			},
		},
	}

	e, err := NewEngine(doc, "v-test")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	matchedTransition, matched, err := e.EvaluatePhaseTransition("intake", EvalContext{
		Args: map[string]any{"promote": true},
	})
	if err != nil {
		t.Fatalf("evaluate phase transition: %v", err)
	}
	if !matched {
		t.Fatal("expected phase transition match")
	}
	if matchedTransition.To != "execution" || matchedTransition.Effect != "permit_transition" {
		t.Fatalf("unexpected transition result: %+v", matchedTransition)
	}

	_, matched, err = e.EvaluatePhaseTransition("intake", EvalContext{
		Args: map[string]any{"promote": false},
	})
	if err != nil {
		t.Fatalf("evaluate phase transition no-match: %v", err)
	}
	if matched {
		t.Fatal("expected no transition match when condition is false")
	}
}

func TestEvaluateNetworkPrimitivesMatchAndMismatch(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "deny",
		Rules: []Rule{
			{
				ID: "allow-specific-network-request",
				Match: Match{
					Tool:   "proxy/http",
					Host:   "api.openai.com",
					Port:   "443",
					Method: "POST",
					Path:   "/v1/*/*",
					Query: map[string]string{
						"api-version": "2024-*",
					},
					Headers: map[string]string{
						"x-api-key": "sk-*",
					},
				},
				Effect: "permit",
			},
		},
	}

	e, err := NewEngine(doc, "v-test")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	permitted := e.Evaluate("proxy/http", EvalContext{
		Args: map[string]any{
			"host":   "api.openai.com",
			"port":   443,
			"method": "POST",
			"path":   "/v1/chat/completions",
			"query": map[string]any{
				"api-version": "2024-10-01",
			},
			"headers": map[string]any{
				"X-API-Key": "sk-live-123",
			},
		},
	})
	if permitted.Effect != "permit" {
		t.Fatalf("expected permit for matching network primitives, got %q", permitted.Effect)
	}

	denied := e.Evaluate("proxy/http", EvalContext{
		Args: map[string]any{
			"host":   "api.openai.com",
			"port":   443,
			"method": "POST",
			"path":   "/v1/chat/completions",
			"query": map[string]any{
				"api-version": "2024-10-01",
			},
			"headers": map[string]any{
				"X-API-Key": "invalid-token",
			},
		},
	})
	if denied.Effect != "deny" {
		t.Fatalf("expected deny when network primitive mismatch occurs, got %q", denied.Effect)
	}
	if denied.ReasonCode != "UNMATCHED_DENY" {
		t.Fatalf("expected UNMATCHED_DENY when no rule matches, got %q", denied.ReasonCode)
	}
}

func TestEvaluateNetworkPrimitivesDerivesFromURLAndRawQuery(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "deny",
		Rules: []Rule{
			{
				ID: "allow-openai-over-url-field",
				Match: Match{
					Tool:   "proxy/http",
					Host:   "*.openai.com",
					Port:   "443,8443,10000-11000",
					Method: "POST",
					Path:   "/v1/*/*",
					Query: map[string]string{
						"model": "gpt-*",
					},
					Headers: map[string]string{
						"x-tenant": "prod",
					},
				},
				Effect: "permit",
			},
		},
	}

	e, err := NewEngine(doc, "v-test")
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	res := e.Evaluate("proxy/http", EvalContext{
		Args: map[string]any{
			"url":       "https://api.openai.com:443/v1/chat/completions?model=gpt-4o",
			"raw_query": "model=gpt-4o&unused=1",
			"method":    "POST",
			"headers": map[string]any{
				"X-Tenant": "prod",
			},
		},
	})

	if res.Effect != "permit" {
		t.Fatalf("expected permit when URL/raw_query-derived fields match, got %q", res.Effect)
	}
}
