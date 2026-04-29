package policy

import (
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

func TestFPLCredentialBlocksPopulateToolTags(t *testing.T) {
	src := `agent demo {
  default deny

  rules {
		defer stripe/refund when principal.verified != true notify: "finance"
  }

  credential stripe {
		scope refund
    max_scope "refund:amount<=500"
  }
}`

	parsed, err := fpl.ParseDocument(src)
	if err != nil {
		t.Fatalf("parse fpl: %v", err)
	}

	doc := fplDocToPolicy(parsed)
	tool, ok := doc.Tools["stripe/refund"]
	if !ok {
		t.Fatalf("expected stripe/refund tool metadata to be populated from credential block")
	}
	if len(doc.Rules) == 0 || doc.Rules[0].Notify != "finance" {
		t.Fatalf("expected notify metadata to be preserved, got rules=%+v", doc.Rules)
	}

	for _, want := range []string{
		"credential:broker",
		"credential:required",
		"credential:scope:refund:amount<=500",
	} {
		if !hasTag(tool.Tags, want) {
			t.Fatalf("expected tag %q in %v", want, tool.Tags)
		}
	}
}

func TestFPLAgentMetadataMappedToVars(t *testing.T) {
	src := `agent meta {
  default deny
  model "gpt-4o"
  framework "langgraph"
  version "1.2.3"

  rules {
    permit http/get
  }
}`

	parsed, err := fpl.ParseDocument(src)
	if err != nil {
		t.Fatalf("parse fpl: %v", err)
	}

	doc := fplDocToPolicy(parsed)
	if got := doc.Vars["agent.model"]; got != "gpt-4o" {
		t.Fatalf("agent.model var mismatch: %v", got)
	}
	if got := doc.Vars["model_name"]; got != "gpt-4o" {
		t.Fatalf("model_name var mismatch: %v", got)
	}
	if got := doc.Vars["agent.framework"]; got != "langgraph" {
		t.Fatalf("agent.framework var mismatch: %v", got)
	}
	if got := doc.Vars["agent.version"]; got != "1.2.3" {
		t.Fatalf("agent.version var mismatch: %v", got)
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
