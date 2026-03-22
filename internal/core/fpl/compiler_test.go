package fpl

import "testing"

func TestCompileRuleBasicSuccess(t *testing.T) {
	rule := &Rule{
		Effect:    "permit",
		Tool:      "stripe_refund",
		Condition: "amount > 100",
		Notify:    "ops",
		Reason:    "manual review",
	}

	compiled, err := CompileRule(rule)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	if compiled.Effect != EffectPermit {
		t.Fatalf("expected permit effect, got %q", compiled.Effect)
	}
	if compiled.Tool != "stripe_refund" {
		t.Fatalf("unexpected tool: %q", compiled.Tool)
	}
	if compiled.When != "amount > 100" {
		t.Fatalf("unexpected when: %q", compiled.When)
	}
	if compiled.Notify == nil || compiled.Notify.Target != "ops" {
		t.Fatalf("unexpected notify metadata: %+v", compiled.Notify)
	}
	if compiled.ReasonCode != "FPL_REASON_MANUAL_REVIEW" {
		t.Fatalf("unexpected reason code: %q", compiled.ReasonCode)
	}
	if compiled.StrictDeny {
		t.Fatalf("expected non-strict rule: %+v", compiled)
	}
}

func TestCompileRuleStrictDenySemantics(t *testing.T) {
	compiled, err := CompileRule(&Rule{
		Effect: "deny!",
		Tool:   "shell.exec",
		Reason: "high refund risk",
	})
	if err != nil {
		t.Fatalf("compile strict deny: %v", err)
	}

	if compiled.Effect != EffectDeny {
		t.Fatalf("strict deny must map to deny, got %q", compiled.Effect)
	}
	if !compiled.StrictDeny {
		t.Fatalf("expected strict deny flag true")
	}
	if compiled.ReasonCode != "FPL_STRICT_DENY_HIGH_REFUND_RISK" {
		t.Fatalf("unexpected strict deny reason code: %q", compiled.ReasonCode)
	}
}

func TestCompileRuleEffectAliasNormalization(t *testing.T) {
	cases := []struct {
		effect string
		want   Effect
	}{
		{effect: "allow", want: EffectPermit},
		{effect: "approve", want: EffectPermit},
		{effect: "block", want: EffectDeny},
		{effect: "reject", want: EffectDeny},
	}

	for _, tc := range cases {
		got, err := CompileRule(&Rule{Effect: tc.effect, Tool: "t"})
		if err != nil {
			t.Fatalf("compile alias %q: %v", tc.effect, err)
		}
		if got.Effect != tc.want {
			t.Fatalf("alias %q expected %q, got %q", tc.effect, tc.want, got.Effect)
		}
	}
}

func TestCompileRuleFailures(t *testing.T) {
	cases := []struct {
		name string
		rule *Rule
	}{
		{name: "nil rule", rule: nil},
		{name: "empty tool", rule: &Rule{Effect: "permit", Tool: "  "}},
		{name: "invalid effect", rule: &Rule{Effect: "explode", Tool: "safe.tool"}},
	}

	for _, tc := range cases {
		if _, err := CompileRule(tc.rule); err == nil {
			t.Fatalf("expected compile error for %s", tc.name)
		}
	}
}

func TestParseAndCompileRules(t *testing.T) {
	src := `allow payout when amount > 10 notify: "ops" reason: "fast path"`
	out, err := ParseAndCompileRules(src)
	if err != nil {
		t.Fatalf("parse+compile: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected one compiled rule, got %d", len(out))
	}
	if out[0].Effect != EffectPermit {
		t.Fatalf("expected allow alias to normalize to permit, got %q", out[0].Effect)
	}
}

func TestParseAndCompileMalformedClauseFails(t *testing.T) {
	src := `permit payout notify:`
	if _, err := ParseAndCompileRules(src); err == nil {
		t.Fatalf("expected parse failure for malformed notify clause")
	}
}
