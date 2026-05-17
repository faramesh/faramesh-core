package fpl

import (
	"testing"
)

func TestParseAgentExtensions(t *testing.T) {
	src := `
agent "payments" {
  rate_limit "stripe/*": 10 per minute
  redact "stripe/charge" args: ["card.number"]
  budget daily {
    max $500.00
    warn_at 0.8
    on_exceed deny
  }
}
`
	doc, err := ParseDocument(src)
	if err != nil {
		t.Fatal(err)
	}
	var ab *AgentBlock
	for _, a := range doc.Agents {
		if a.ID == "payments" {
			ab = a
			break
		}
	}
	if ab == nil {
		t.Fatal("missing agent block")
	}
	if len(ab.RateLimits) != 1 || ab.RateLimits[0].Limit != 10 {
		t.Fatalf("rate_limits: %+v", ab.RateLimits)
	}
	if len(ab.Redactions) != 1 || ab.Redactions[0].Paths[0] != "card.number" {
		t.Fatalf("redactions: %+v", ab.Redactions)
	}
	if len(ab.Budgets) != 1 || ab.Budgets[0].WarnAt != 0.8 {
		t.Fatalf("budget warn_at: %+v", ab.Budgets)
	}
}
