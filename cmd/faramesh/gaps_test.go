package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

func TestBuildGapsReportWithPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
faramesh-version: "1.0"
agent-id: "gap-test"
default_effect: deny
rules:
  - id: permit-search
    effect: permit
    reason: search is allowed
    match:
      tool: "search/*"
      when: "true"
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	report, err := buildGapsReport(
		"/repo",
		"/data",
		policyPath,
		&runtimeenv.DiscoveryReport{
			CandidateTools: []runtimeenv.DiscoveredTool{
				{ID: "search/web"},
				{ID: "email/send"},
			},
		},
		[]toolinventory.Entry{
			{ToolID: "search/web", PolicyRuleIDs: []string{"permit-search"}},
			{ToolID: "shell/run"},
		},
	)
	if err != nil {
		t.Fatalf("buildGapsReport: %v", err)
	}

	if !slices.Contains(report.StaticNotObserved, "email/send") {
		t.Fatalf("expected email/send in static-not-observed: %+v", report.StaticNotObserved)
	}
	if !slices.Contains(report.ObservedNotStatic, "shell/run") {
		t.Fatalf("expected shell/run in observed-not-static: %+v", report.ObservedNotStatic)
	}
	if !slices.Contains(report.ObservedNotPolicy, "shell/run") {
		t.Fatalf("expected shell/run in observed-not-policy: %+v", report.ObservedNotPolicy)
	}
	if !slices.Contains(report.StaticNotPolicy, "email/send") {
		t.Fatalf("expected email/send in static-not-policy: %+v", report.StaticNotPolicy)
	}
	if !slices.Contains(report.ShadowOnlyGovernance, "shell/run") {
		t.Fatalf("expected shell/run in shadow-only: %+v", report.ShadowOnlyGovernance)
	}
	if slices.Contains(report.ObservedNotPolicy, "search/web") {
		t.Fatalf("search/web should be policy-covered: %+v", report.ObservedNotPolicy)
	}
}

func TestBuildGapsReportWithoutPolicyFallsBackToRuntimeRuleIDs(t *testing.T) {
	report, err := buildGapsReport(
		"/repo",
		"/data",
		"",
		&runtimeenv.DiscoveryReport{
			CandidateTools: []runtimeenv.DiscoveredTool{{ID: "search/web"}},
		},
		[]toolinventory.Entry{
			{ToolID: "search/web", PolicyRuleIDs: []string{"rule-1"}},
			{ToolID: "http/post"},
		},
	)
	if err != nil {
		t.Fatalf("buildGapsReport: %v", err)
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected warning when policy is omitted")
	}
	if !slices.Contains(report.ObservedNotPolicy, "http/post") {
		t.Fatalf("expected http/post in observed-not-policy: %+v", report.ObservedNotPolicy)
	}
	if slices.Contains(report.ObservedNotPolicy, "search/web") {
		t.Fatalf("search/web should be considered covered via runtime rule IDs: %+v", report.ObservedNotPolicy)
	}
}
