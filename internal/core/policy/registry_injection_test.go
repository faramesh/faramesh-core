package policy

import (
	"context"
	"testing"
)

func TestOperatorRegistryInjectedIntoEvalEnv(t *testing.T) {
	if err := DefaultOperatorRegistry().Register(OperatorMeta{
		Name:          "risk_score",
		Deterministic: true,
		ReturnType:    "number",
	}, func(args ...any) (any, error) {
		return 0.95, nil
	}); err != nil {
		t.Fatalf("register operator: %v", err)
	}

	doc, ver, err := LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: "t"
rules:
  - id: deny-risk
    match:
      tool: "transfer"
      when: "risk_score(args.account_id) > 0.8"
    effect: deny
default_effect: permit
`))
	if err != nil {
		t.Fatalf("load doc: %v", err)
	}
	e, err := NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile engine: %v", err)
	}

	res := e.Evaluate("transfer", EvalContext{Args: map[string]any{"account_id": "a1"}})
	if res.Effect != "deny" {
		t.Fatalf("expected deny from custom operator, got %s", res.Effect)
	}
}

func TestSelectorRegistryInjectedIntoEvalEnv(t *testing.T) {
	if err := DefaultSelectorRegistry().Register(SelectorMeta{
		Name:      "feature_flag",
		Namespace: "data",
	}, func(ctx context.Context, args ...any) (any, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("register selector: %v", err)
	}

	doc, ver, err := LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: "t"
rules:
  - id: permit-flag
    match:
      tool: "x"
      when: "data.feature_flag('new_billing') == true"
    effect: permit
default_effect: deny
`))
	if err != nil {
		t.Fatalf("load doc: %v", err)
	}
	e, err := NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile engine: %v", err)
	}
	res := e.Evaluate("x", EvalContext{Args: map[string]any{}})
	if res.Effect != "permit" {
		t.Fatalf("expected permit from selector, got %s", res.Effect)
	}
}
