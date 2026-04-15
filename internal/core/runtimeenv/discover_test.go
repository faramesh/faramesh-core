package runtimeenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverProjectFindsFrameworksAndSignals(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"@langchain/core":"^1.0.0","@modelcontextprotocol/sdk":"^1.0.0"}}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "mcp.json"), []byte(`{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}`), 0o644); err != nil {
		t.Fatalf("write mcp.json: %v", err)
	}
	code := `
import subprocess
import os

TOOL_ID = "shell/exec"
API_URL = "https://api.example.com/v1"

os.getenv("SECRET_TOKEN")
subprocess.run(["ls", "-la"])
`
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte(code), 0o644); err != nil {
		t.Fatalf("write agent.py: %v", err)
	}

	report := DiscoverProject(root)
	if report == nil {
		t.Fatal("DiscoverProject() returned nil")
	}
	if len(report.Frameworks) == 0 {
		t.Fatalf("expected discovered frameworks, got none")
	}
	if !contains(report.Frameworks, "langchain-js") {
		t.Fatalf("frameworks = %#v, want langchain-js", report.Frameworks)
	}
	if !contains(report.Frameworks, "mcp-node-sdk") {
		t.Fatalf("frameworks = %#v, want mcp-node-sdk", report.Frameworks)
	}
	if len(report.MCPConfigFiles) != 1 || report.MCPConfigFiles[0] != "mcp.json" {
		t.Fatalf("mcp config files = %#v, want [mcp.json]", report.MCPConfigFiles)
	}
	if len(report.NetworkReferences) == 0 {
		t.Fatalf("expected network references, got none")
	}
	if len(report.ShellReferences) == 0 {
		t.Fatalf("expected shell references, got none")
	}
	if len(report.CredentialReferences) == 0 {
		t.Fatalf("expected credential references, got none")
	}
	foundShellTool := false
	for _, tool := range report.CandidateTools {
		if tool.ID == "shell/exec" {
			foundShellTool = true
			break
		}
	}
	if !foundShellTool {
		t.Fatalf("candidate tools = %#v, want shell/exec", report.CandidateTools)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
