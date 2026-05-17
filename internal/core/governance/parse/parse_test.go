package parse_test

import (
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/governance"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"github.com/faramesh/faramesh-core/internal/core/governance/parse"
)

func TestDetectSyntax(t *testing.T) {
	tests := []struct {
		path string
		body string
		want ast.Syntax
	}{
		{"governance.fms", "runtime { mode = enforce }", ast.SyntaxFPL},
		{"governance.fms", "---\nruntime:\n  mode: enforce\n", ast.SyntaxYAML},
		{"governance.fms", `{"runtime":{"mode":"enforce"}}`, ast.SyntaxJSON},
		{"governance.fms.yaml", "", ast.SyntaxYAML},
		{"governance.fms.json", "", ast.SyntaxJSON},
	}
	for _, tc := range tests {
		got := parse.DetectSyntax(tc.path, []byte(tc.body))
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.path, got, tc.want)
		}
	}
}

func TestParseFPLAndYAMLEquivalence(t *testing.T) {
	fplSrc := `
import "registry.faramesh.dev/frameworks/langgraph@1.0.0"
runtime {
  mode = enforce
  wal_dir = "./faramesh-wal"
}
agent "my-app-agent" {
  rules {
    defer search_docs
  }
}
`
	yamlSrc := `---
imports:
  - ref: registry.faramesh.dev/frameworks/langgraph@1.0.0
runtime:
  mode: enforce
  wal_dir: ./faramesh-wal
agents:
  my-app-agent:
    rules:
      - effect: defer
        tool: search_docs
`
	fplDoc, err := governance.ParseSource("governance.fms", []byte(fplSrc))
	if err != nil {
		t.Fatalf("fpl: %v", err)
	}
	yamlDoc, err := governance.ParseSource("governance.fms.yaml", []byte(yamlSrc))
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if fplDoc.Runtime == nil || yamlDoc.Runtime == nil {
		t.Fatal("expected runtime blocks")
	}
	if fplDoc.Runtime.Mode != yamlDoc.Runtime.Mode {
		t.Fatalf("mode: fpl=%q yaml=%q", fplDoc.Runtime.Mode, yamlDoc.Runtime.Mode)
	}
	if len(fplDoc.Imports) != len(yamlDoc.Imports) {
		t.Fatalf("imports: fpl=%d yaml=%d", len(fplDoc.Imports), len(yamlDoc.Imports))
	}
	if _, ok := fplDoc.Agents["my-app-agent"]; !ok {
		t.Fatal("missing fpl agent")
	}
	if _, ok := yamlDoc.Agents["my-app-agent"]; !ok {
		t.Fatal("missing yaml agent")
	}
}

func TestParseYAMLAgentExtensionsEquivalence(t *testing.T) {
	fplSrc := `
agent "payments" {
  rate_limit "stripe/*": 10 per minute
  redact "stripe/charge" args: ["card.number"]
  budget daily {
    max $500.00
    warn_at 0.8
    on_exceed deny
  }
  rules {
    permit health/*
  }
}
`
	yamlSrc := `---
agents:
  payments:
    rate_limits:
      - tool: stripe/*
        limit: 10
        window: minute
    redactions:
      - tool: stripe/charge
        paths: [card.number]
    budgets:
      - scope: daily
        max: 500
        warn_at: 0.8
        on_exceed: deny
    rules:
      - effect: permit
        tool: health/*
`
	fplDoc, err := governance.ParseSource("governance.fms", []byte(fplSrc))
	if err != nil {
		t.Fatalf("fpl: %v", err)
	}
	yamlDoc, err := governance.ParseSource("governance.fms.yaml", []byte(yamlSrc))
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	fplAg := fplDoc.Agents["payments"]
	yamlAg := yamlDoc.Agents["payments"]
	if fplAg == nil || yamlAg == nil {
		t.Fatal("missing payments agent")
	}
	if len(fplAg.RateLimits) != 1 || len(yamlAg.RateLimits) != 1 {
		t.Fatalf("rate_limits fpl=%d yaml=%d", len(fplAg.RateLimits), len(yamlAg.RateLimits))
	}
	if fplAg.RateLimits[0].Limit != yamlAg.RateLimits[0].Limit {
		t.Fatalf("limit: fpl=%d yaml=%d", fplAg.RateLimits[0].Limit, yamlAg.RateLimits[0].Limit)
	}
	if len(fplAg.Redactions) != 1 || len(yamlAg.Redactions) != 1 {
		t.Fatalf("redactions mismatch")
	}
	if len(fplAg.Budgets) != 1 || len(yamlAg.Budgets) != 1 {
		t.Fatalf("budgets mismatch")
	}
	if fplAg.Budgets[0].WarnAt != yamlAg.Budgets[0].WarnAt {
		t.Fatalf("warn_at: fpl=%v yaml=%v", fplAg.Budgets[0].WarnAt, yamlAg.Budgets[0].WarnAt)
	}
}

func TestParseJSONDenyUnconditional(t *testing.T) {
	jsonSrc := `{
  "agents": {
    "bot": {
      "rules": [
        { "deny_unconditional": "shell/exec" }
      ]
    }
  }
}`
	doc, err := governance.ParseSource("governance.fms.json", []byte(jsonSrc))
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	ag := doc.Agents["bot"]
	if len(ag.Rules) != 1 || ag.Rules[0].Effect != "deny!" || ag.Rules[0].Tool != "shell/exec" {
		t.Fatalf("rule: %+v", ag.Rules)
	}
}
