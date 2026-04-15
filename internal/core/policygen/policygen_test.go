package policygen

import (
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

func TestGenerateBuildsConservativeStarterPolicy(t *testing.T) {
	result := Generate([]toolinventory.Entry{
		{
			ToolID:           "search/web",
			TotalInvocations: 8,
			CoverageTier:     "A",
			Effects:          map[string]int{"PERMIT": 8},
		},
		{
			ToolID:           "shell/run",
			TotalInvocations: 3,
			CoverageTier:     "B",
			Effects:          map[string]int{"DEFER": 3},
		},
		{
			ToolID:           "credential/fetch",
			TotalInvocations: 2,
			CoverageTier:     "A",
			Effects:          map[string]int{"PERMIT": 2},
		},
	}, Options{AgentID: "cursor-agent"})

	if result.Doc == nil {
		t.Fatalf("expected policy doc")
	}
	if result.Doc.AgentID != "cursor-agent" {
		t.Fatalf("agent id = %q, want cursor-agent", result.Doc.AgentID)
	}
	if result.Doc.DefaultEffect != "deny" {
		t.Fatalf("default_effect = %q, want deny", result.Doc.DefaultEffect)
	}
	if len(result.Recommendations) != 3 {
		t.Fatalf("recommendations = %d, want 3", len(result.Recommendations))
	}
	if result.Doc.Budget == nil || result.Doc.Budget.MaxCalls != 50 || result.Doc.Budget.OnExceed != "defer" {
		t.Fatalf("unexpected budget suggestion: %+v", result.Doc.Budget)
	}

	ruleByID := map[string]string{}
	for _, rule := range result.Doc.Rules {
		ruleByID[rule.Match.Tool] = rule.Effect
	}
	if got := ruleByID["search/web"]; got != "permit" {
		t.Fatalf("search/web effect = %q, want permit", got)
	}
	if got := ruleByID["shell/run"]; got != "defer" {
		t.Fatalf("shell/run effect = %q, want defer", got)
	}
	if got := ruleByID["credential/fetch"]; got != "defer" {
		t.Fatalf("credential/fetch effect = %q, want defer", got)
	}

	foundShellGuard := false
	for _, rule := range result.Doc.Rules {
		if rule.ID == "deny-destructive-shell" && rule.Match.Tool == "shell/*" && rule.Effect == "deny" {
			foundShellGuard = true
		}
	}
	if !foundShellGuard {
		t.Fatalf("expected destructive shell guard in generated rules")
	}

	credTool := result.Doc.Tools["credential/fetch"]
	if !strings.Contains(strings.Join(credTool.Tags, ","), "credential:broker") {
		t.Fatalf("credential tags missing broker marker: %+v", credTool.Tags)
	}
}

func TestGenerateDowngradesWeakCoverageReadOnlyTools(t *testing.T) {
	result := Generate([]toolinventory.Entry{
		{
			ToolID:           "file/read",
			TotalInvocations: 4,
			CoverageTier:     "E",
			Effects:          map[string]int{"PERMIT": 4},
		},
	}, Options{})

	if len(result.Doc.Rules) == 0 {
		t.Fatalf("expected generated rules")
	}
	if got := result.Doc.Rules[0].Effect; got != "defer" {
		t.Fatalf("weak coverage read-only tool effect = %q, want defer", got)
	}
}

func TestRenderYAMLProducesLoadablePolicy(t *testing.T) {
	result := Generate([]toolinventory.Entry{
		{
			ToolID:           "search/web",
			TotalInvocations: 5,
			CoverageTier:     "A",
			Effects:          map[string]int{"PERMIT": 5},
		},
	}, Options{AgentID: "starter"})

	out, err := RenderYAML(result)
	if err != nil {
		t.Fatalf("render yaml: %v", err)
	}
	doc, _, err := policy.LoadBytes(out)
	if err != nil {
		t.Fatalf("load generated yaml: %v", err)
	}
	if doc.AgentID != "starter" {
		t.Fatalf("loaded agent id = %q, want starter", doc.AgentID)
	}
	if len(policy.Validate(doc)) > 0 {
		t.Fatalf("generated policy should validate cleanly: %+v", policy.Validate(doc))
	}
}
