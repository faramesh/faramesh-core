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
