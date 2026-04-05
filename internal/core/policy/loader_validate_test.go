package policy

import (
	"strings"
	"testing"
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
