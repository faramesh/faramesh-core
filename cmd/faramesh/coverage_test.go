package main

import (
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

func TestBuildCoverageReportCombinesStaticAndRuntimeTools(t *testing.T) {
	discovery := &runtimeenv.DiscoveryReport{
		Environment: &runtimeenv.DetectedEnvironment{Runtime: "local", Framework: "langchain"},
		CandidateTools: []runtimeenv.DiscoveredTool{
			{ID: "tools/call", Surface: "mcp", Source: "mcp-config", File: "mcp.json"},
			{ID: "shell/exec", Surface: "shell", Source: "static-signal", File: "agent.py"},
		},
	}
	entries := []toolinventory.Entry{
		{
			ToolID:            "shell/exec",
			TotalInvocations:  3,
			CoverageTier:      "B",
			Effects:           map[string]int{"DENY": 2, "PERMIT": 1},
			InterceptAdapters: []string{"sdk"},
			PolicyRuleIDs:     []string{"deny-shell"},
		},
	}

	report := buildCoverageReport("/repo", "/data", discovery, entries)
	if report.Summary.ObservedTools != 1 {
		t.Fatalf("observed tools = %d, want 1", report.Summary.ObservedTools)
	}
	if report.Summary.StaticTools != 2 {
		t.Fatalf("static tools = %d, want 2", report.Summary.StaticTools)
	}
	if report.Summary.CombinedTools != 2 {
		t.Fatalf("combined tools = %d, want 2", report.Summary.CombinedTools)
	}

	var shell, mcp coverageTool
	for _, tool := range report.Tools {
		switch tool.ToolID {
		case "shell/exec":
			shell = tool
		case "tools/call":
			mcp = tool
		}
	}
	if shell.Source != "both" || !shell.Observed || !shell.StaticDiscovered {
		t.Fatalf("shell source/flags = %#v, want both+observed+static", shell)
	}
	if shell.CoverageTier != "B" {
		t.Fatalf("shell coverage tier = %q, want B", shell.CoverageTier)
	}
	if mcp.CoverageTier != "E" || mcp.Observed {
		t.Fatalf("mcp tool = %#v, want static-only tier E", mcp)
	}
	if len(mcp.KnownGaps) == 0 {
		t.Fatalf("expected known gaps for static-only tools")
	}
}
