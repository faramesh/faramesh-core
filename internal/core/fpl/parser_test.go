package fpl

import "testing"

func TestParseRulesBasic(t *testing.T) {
	src := `
permit stripe_refund
deny shell_exec
defer payout
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if rules[0].Effect != "permit" || rules[0].Tool != "stripe_refund" {
		t.Fatalf("unexpected first rule: %+v", rules[0])
	}
	if rules[0].Condition != "" || rules[0].Notify != "" || rules[0].Reason != "" {
		t.Fatalf("expected empty optional fields for first rule: %+v", rules[0])
	}
	if rules[2].Effect != "defer" || rules[2].Tool != "payout" {
		t.Fatalf("unexpected third rule: %+v", rules[2])
	}
}

func TestParseRulesWithComments(t *testing.T) {
	src := `
# deny dangerous execution
deny shell_exec
# only observe large payment action
defer payment/charge when amount > 100
`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatalf("parse with comments: %v", err)
	}
	if len(rules) != 2 || rules[0].Tool != "shell_exec" {
		t.Fatalf("unexpected parse result: %+v", rules)
	}
	if rules[1].Condition != "amount > 100" {
		t.Fatalf("unexpected condition parse: %+v", rules[1])
	}
}

func TestParseRulesWithAllOptionalClauses(t *testing.T) {
	src := `deny! shell.exec when risk_score(args.user) > 0.8 notify: "ops" reason: "high refund"`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatalf("parse full clause rule: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Effect != "deny!" || r.Tool != "shell.exec" {
		t.Fatalf("unexpected effect/tool parse: %+v", r)
	}
	if r.Condition != "risk_score(args.user) > 0.8" {
		t.Fatalf("unexpected condition parse: %+v", r)
	}
	if r.Notify != "ops" {
		t.Fatalf("unexpected notify parse: %+v", r)
	}
	if r.Reason != "high refund" {
		t.Fatalf("unexpected reason parse: %+v", r)
	}
}

func TestParseRulesWhenSupportsSingleQuotedStrings(t *testing.T) {
	src := `permit http/get when args.endpoint == 'https://safe.example'`
	rules, err := ParseRules(src)
	if err != nil {
		t.Fatalf("parse single-quoted when expression: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Condition != `args.endpoint == "https://safe.example"` {
		t.Fatalf("unexpected normalized condition: %q", rules[0].Condition)
	}
}
