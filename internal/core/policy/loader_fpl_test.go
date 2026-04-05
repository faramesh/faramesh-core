package policy

import (
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

func TestFPLCredentialBlocksPopulateToolTags(t *testing.T) {
	src := `agent demo {
  default deny

  rules {
    deny stripe/refund when principal.verified != true
  }

  credential stripe {
    scope stripe/refund
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

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
