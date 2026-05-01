package core

import (
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func TestGovernOutput_DefersOnMatchingPolicyRule(t *testing.T) {
	const policyYAML = `
faramesh-version: "1"
agent-id: "output-gov-test"
default-effect: "permit"
rules:
  - id: allow-all
    effect: permit
    match:
      tool: "*"
output_policies:
  - output_type: aggregate
    rules:
      - id: defer-sensitive
        scan:
          entity_extraction: true
        condition: "entity_count > 0"
        on_match: defer
        reason: "human approval required"
`

	p := buildPipelineFromYAML(t, policyYAML)
	res := p.GovernOutput(GovernOutputRequest{
		AgentID:        "orch-1",
		SessionID:      "sess-1",
		OutputType:     "aggregate",
		Output:         "contact alice@example.com",
		SourceAgentIDs: []string{"worker-a", "worker-b"},
	})

	if res.Outcome != OutputOutcomeDeferred {
		t.Fatalf("outcome=%q, want %q", res.Outcome, OutputOutcomeDeferred)
	}
	if res.ReasonCode != reasons.OutputSchemaDefer {
		t.Fatalf("reason_code=%q, want %q", res.ReasonCode, reasons.OutputSchemaDefer)
	}
	if strings.TrimSpace(res.DeferToken) == "" {
		t.Fatal("expected defer token")
	}
}

func TestGovernOutput_DeniesOnMatchingPolicyRule(t *testing.T) {
	const policyYAML = `
faramesh-version: "1"
agent-id: "output-gov-test"
default-effect: "permit"
rules:
  - id: allow-all
    effect: permit
    match:
      tool: "*"
output_policies:
  - output_type: aggregate
    rules:
      - id: deny-large
        scan:
          entity_extraction: true
        condition: "output_len > 5"
        on_match: deny
        reason: "too large"
`

	p := buildPipelineFromYAML(t, policyYAML)
	res := p.GovernOutput(GovernOutputRequest{
		AgentID:    "orch-1",
		SessionID:  "sess-2",
		OutputType: "aggregate",
		Output:     "0123456789",
	})

	if res.Outcome != OutputOutcomeDenied {
		t.Fatalf("outcome=%q, want %q", res.Outcome, OutputOutcomeDenied)
	}
	if res.ReasonCode != reasons.OutputSchemaDeny {
		t.Fatalf("reason_code=%q, want %q", res.ReasonCode, reasons.OutputSchemaDeny)
	}
}

func TestGovernOutput_UsesAggregationGovernorRedaction(t *testing.T) {
	const policyYAML = `
faramesh-version: "1"
agent-id: "output-gov-test"
default-effect: "permit"
rules:
  - id: allow-all
    effect: permit
    match:
      tool: "*"
`

	p := buildPipelineFromYAML(t, policyYAML)
	p.aggGovernor = multiagent.NewAggregationGovernor(multiagent.AggregatePolicy{
		BlockedEntityTypes: []string{"email"},
	})
	p.aggGovernor.SetSemanticDriftObserver(observe.Default)

	res := p.GovernOutput(GovernOutputRequest{
		AgentID:    "orch-1",
		SessionID:  "sess-3",
		OutputType: "aggregate",
		Output:     "email bob@example.com",
	})

	if res.Outcome != OutputOutcomeRedacted {
		t.Fatalf("outcome=%q, want %q", res.Outcome, OutputOutcomeRedacted)
	}
	if !strings.Contains(res.SanitizedOutput, "[REDACTED]") {
		t.Fatalf("expected redacted output, got %q", res.SanitizedOutput)
	}
}

func TestGovernOutput_DeniesOnInvalidOutputRuleConfig(t *testing.T) {
	const policyYAML = `
faramesh-version: "1"
agent-id: "output-gov-test"
default-effect: "permit"
rules:
  - id: allow-all
    effect: permit
    match:
      tool: "*"
output_policies:
  - output_type: aggregate
    rules:
      - id: invalid-action
        scan:
          entity_extraction: true
        condition: "entity_count > 0"
        on_match: block
`

	p := buildPipelineFromYAML(t, policyYAML)
	res := p.GovernOutput(GovernOutputRequest{
		AgentID:    "orch-1",
		SessionID:  "sess-invalid",
		OutputType: "aggregate",
		Output:     "contact alice@example.com",
	})

	if res.Outcome != OutputOutcomeDenied {
		t.Fatalf("outcome=%q, want %q", res.Outcome, OutputOutcomeDenied)
	}
	if res.ReasonCode != reasons.OutputSchemaDeny {
		t.Fatalf("reason_code=%q, want %q", res.ReasonCode, reasons.OutputSchemaDeny)
	}
	if !strings.Contains(strings.ToLower(res.Reason), "unsupported on_match") {
		t.Fatalf("expected unsupported on_match error, got %q", res.Reason)
	}
}

func TestGovernOutput_DeduplicatesSourceAgentIDs(t *testing.T) {
	const policyYAML = `
faramesh-version: "1"
agent-id: "output-gov-test"
default-effect: "permit"
rules:
  - id: allow-all
    effect: permit
    match:
      tool: "*"
output_policies:
  - output_type: aggregate
    rules:
      - id: defer-unique-sources
        scan:
          entity_extraction: true
        condition: "source_count == 2"
        on_match: defer
        reason: "needs review"
`

	p := buildPipelineFromYAML(t, policyYAML)
	res := p.GovernOutput(GovernOutputRequest{
		AgentID:        "orch-1",
		SessionID:      "sess-sources",
		OutputType:     "aggregate",
		Output:         "contact bob@example.com",
		SourceAgentIDs: []string{"worker-a", "worker-a", "worker-b"},
	})

	if res.Outcome != OutputOutcomeDeferred {
		t.Fatalf("outcome=%q, want %q", res.Outcome, OutputOutcomeDeferred)
	}
}

func TestGovernOutput_DeferTokenDeterministic(t *testing.T) {
	const policyYAML = `
faramesh-version: "1"
agent-id: "output-gov-test"
default-effect: "permit"
rules:
  - id: allow-all
    effect: permit
    match:
      tool: "*"
output_policies:
  - output_type: aggregate
    rules:
      - id: defer-sensitive
        scan:
          entity_extraction: true
        condition: "entity_count > 0"
        on_match: defer
        reason: "human approval required"
`

	p := buildPipelineFromYAML(t, policyYAML)
	req := GovernOutputRequest{
		AgentID:        "orch-1",
		SessionID:      "sess-deterministic",
		OutputType:     "aggregate",
		Output:         "contact alice@example.com",
		SourceAgentIDs: []string{"worker-a", "worker-b"},
	}

	res1 := p.GovernOutput(req)
	res2 := p.GovernOutput(req)

	if strings.TrimSpace(res1.DeferToken) == "" {
		t.Fatalf("expected defer token on first call")
	}
	if res1.DeferToken != res2.DeferToken {
		t.Fatalf("defer token drift: first=%q second=%q", res1.DeferToken, res2.DeferToken)
	}
}
