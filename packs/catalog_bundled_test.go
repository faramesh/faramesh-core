package packs

import (
	"slices"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/hub"
)

var requiredP2PackNames = []string{
	"faramesh/p2-research-agent",
	"faramesh/p2-ops-release",
	"faramesh/p2-network-controls",
	"faramesh/p2-marketing-agent",
	"faramesh/p2-data-agent",
	"faramesh/p2-customer-success",
	"faramesh/p2-docs-writer",
	"faramesh/p2-webhook-agent",
	"faramesh/p2-vendor-diligence",
	"faramesh/p2-email-outbound",
	"faramesh/p2-multi-agent",
}

// Phase 5 / §5.12b: every embedded bundled pack must resolve, validate, compile, and round-trip through hub install.
func TestBundledPacksLookupValidateAndInstall(t *testing.T) {
	t.Parallel()
	summaries := Search("")
	if len(summaries) < 18 {
		t.Fatalf("expected at least 18 bundled pack summaries from Search(\"\") (incl. P2 seeds), got %d", len(summaries))
	}
	names := make([]string, 0, len(summaries))
	for _, s := range summaries {
		names = append(names, s.Name)
	}
	for _, want := range requiredP2PackNames {
		if !slices.Contains(names, want) {
			t.Fatalf("bundled catalog missing required P2 pack %q (have: %v)", want, names)
		}
	}
	for _, s := range summaries {
		s := s
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			pv, err := Lookup(s.Name, s.LatestVersion)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if pv == nil || pv.PolicyYAML == "" {
				t.Fatal("empty PolicyYAML")
			}
			if strings.TrimSpace(pv.PolicyFPL) == "" {
				t.Fatalf("bundled pack %q must ship policy.fpl beside policy.yaml (manifest policy_fpl_sha256)", s.Name)
			}
			doc, _, err := policy.LoadBytes([]byte(pv.PolicyYAML))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			issues := policy.Validate(doc)
			if errs := policy.ValidationErrorsOnly(issues); len(errs) > 0 {
				t.Fatalf("Validate: %v", errs)
			}
			if _, err := policy.NewEngine(doc, "bundled-pack-test"); err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			root := t.TempDir()
			if _, err := hub.WritePackToDiskWithMode(root, pv, "enforce"); err != nil {
				t.Fatalf("WritePackToDiskWithMode: %v", err)
			}
		})
	}
}
