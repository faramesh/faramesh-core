package policy

import (
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

func TestValidateAcceptsPrincipalAndDelegationSymbols(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "deny",
		Rules: []Rule{
			{
				ID: "principal-aware",
				Match: Match{
					Tool: "http/get",
					When: "principal.verified == true && delegation.depth >= 0",
				},
				Effect: "permit",
			},
		},
	}

	issues := Validate(doc)
	for _, issue := range issues {
		if strings.Contains(issue, "invalid when expression") {
			t.Fatalf("unexpected when validation failure: %s", issue)
		}
	}
}

func TestValidateRejectsInvalidPhaseTransitionExpression(t *testing.T) {
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
				Conditions: "unknown_symbol > 0",
				Effect:     "permit_transition",
			},
		},
	}

	issues := Validate(doc)
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, "phase_transition") {
		t.Fatalf("expected phase_transition validation issue, got: %s", joined)
	}
	if !strings.Contains(joined, "invalid conditions expression") {
		t.Fatalf("expected invalid conditions expression issue, got: %s", joined)
	}
}

func TestValidateRejectsInvalidPhaseTransitionEffect(t *testing.T) {
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
				Conditions: "true",
				Effect:     "allow_now",
			},
		},
	}

	issues := Validate(doc)
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, "invalid effect") {
		t.Fatalf("expected invalid effect issue, got: %s", joined)
	}
}

func TestValidateRejectsInvalidNetworkMatchSelectors(t *testing.T) {
	doc := &Doc{
		DefaultEffect: "deny",
		Rules: []Rule{
			{
				ID: "bad-network-selectors",
				Match: Match{
					Tool: "proxy/http",
					Port: "0-70000",
					Query: map[string]string{
						"": "x",
					},
					Headers: map[string]string{
						" ": "y",
					},
				},
				Effect: "permit",
			},
		},
	}

	issues := Validate(doc)
	joined := strings.Join(issues, "\n")
	if !strings.Contains(joined, "invalid match.port") {
		t.Fatalf("expected invalid match.port issue, got: %s", joined)
	}
	if !strings.Contains(joined, "match.query contains empty key") {
		t.Fatalf("expected empty query key issue, got: %s", joined)
	}
	if !strings.Contains(joined, "match.headers contains empty key") {
		t.Fatalf("expected empty header key issue, got: %s", joined)
	}
}

func TestFPLRuleToPolicyRuleIncludesNetworkSelectors(t *testing.T) {
	r := fplRuleToRule(&fpl.Rule{
		Effect: "permit",
		Tool:   "proxy/http",
		Host:   "api.openai.com",
		Port:   "443",
		Method: "POST",
		Path:   "/v1/*",
		Query: map[string]string{
			"model": "gpt-*",
		},
		Headers: map[string]string{
			"x-org": "acme",
		},
		Condition: "true",
	}, 1)

	if r.Match.Host != "api.openai.com" || r.Match.Port != "443" || r.Match.Method != "POST" || r.Match.Path != "/v1/*" {
		t.Fatalf("unexpected lowered network selectors: %+v", r.Match)
	}
	if r.Match.Query["model"] != "gpt-*" {
		t.Fatalf("unexpected lowered query selector: %+v", r.Match.Query)
	}
	if r.Match.Headers["x-org"] != "acme" {
		t.Fatalf("unexpected lowered header selector: %+v", r.Match.Headers)
	}
}
