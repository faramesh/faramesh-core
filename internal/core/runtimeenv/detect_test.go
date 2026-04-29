package runtimeenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectRuntime_k8s(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Cleanup(func() { _ = os.Unsetenv("KUBERNETES_SERVICE_HOST") })
	d := DetectEnvironment(t.TempDir())
	if d.Runtime != "k8s" {
		t.Fatalf("runtime: got %q want k8s", d.Runtime)
	}
	if d.TrustLevel != "strong" {
		t.Fatalf("trust: got %q want strong", d.TrustLevel)
	}
}

func TestDetectRuntime_lambda(t *testing.T) {
	t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "fn")
	t.Cleanup(func() { _ = os.Unsetenv("AWS_LAMBDA_FUNCTION_NAME") })
	d := DetectEnvironment(t.TempDir())
	if d.Runtime != "lambda" {
		t.Fatalf("runtime: got %q want lambda", d.Runtime)
	}
	if d.TrustLevel != "credential_only" {
		t.Fatalf("trust: got %q want credential_only", d.TrustLevel)
	}
}

func TestApplyFarameshEnv(t *testing.T) {
	d := &DetectedEnvironment{
		TrustLevel:   "strong",
		AdapterLevel: 3,
		Runtime:      "local",
		Framework:    "langgraph",
	}
	env := ApplyFarameshEnv([]string{"PATH=/usr/bin"}, d, "/pol/p.yaml")
	found := map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		found[k] = v
	}
	if found["FARAMESH_TRUST_LEVEL"] != "strong" {
		t.Fatalf("trust env: %v", found)
	}
	if found["FARAMESH_ADAPTER_LEVEL"] != "3" {
		t.Fatalf("adapter env: %v", found)
	}
	if found["FARAMESH_POLICY_PATH"] != "/pol/p.yaml" {
		t.Fatalf("policy env: %v", found)
	}
}

func TestDetectFrameworkFromPyProject(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(`
[project]
dependencies = [
  "langgraph>=0.2",
  "langchain-core",
]
`), 0o644)
	d := DetectEnvironment(dir)
	if d.Framework != "langgraph" {
		t.Fatalf("framework: got %q want langgraph", d.Framework)
	}
}

func TestDetectFrameworkFromPyProject_NewFrameworkTokens(t *testing.T) {
	tests := []struct {
		name      string
		deps      []string
		want      string
		assertHas []string
	}{
		{
			name:      "google adk",
			deps:      []string{"google-adk>=1.0"},
			want:      "google-adk",
			assertHas: []string{"google-adk"},
		},
		{
			name:      "strands agents builder alias",
			deps:      []string{"strands-agents-builder>=0.1"},
			want:      "strands-agents",
			assertHas: []string{"strands-agents-builder"},
		},
		{
			name:      "bedrock agentcore",
			deps:      []string{"bedrock-agentcore>=0.3"},
			want:      "bedrock-agentcore",
			assertHas: []string{"bedrock-agentcore"},
		},
		{
			name:      "strands agents core",
			deps:      []string{"strands-agents>=0.2"},
			want:      "strands-agents",
			assertHas: []string{"strands-agents"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			var b strings.Builder
			b.WriteString("[project]\n")
			b.WriteString("dependencies = [\n")
			for _, dep := range tt.deps {
				b.WriteString("  \"" + dep + "\",\n")
			}
			b.WriteString("]\n")
			if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(b.String()), 0o644); err != nil {
				t.Fatalf("write pyproject: %v", err)
			}

			d := DetectEnvironment(dir)
			if d.Framework != tt.want {
				t.Fatalf("framework: got %q want %q", d.Framework, tt.want)
			}

			deps := ScanPythonDeps(dir)
			for _, pkg := range tt.assertHas {
				if !deps.Has(pkg) {
					t.Fatalf("expected dependency set to contain %q", pkg)
				}
			}
		})
	}
}

func TestDetectAgentHarness_DeepAgentsMarkerPreferred(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".deepagents"), 0o755); err != nil {
		t.Fatalf("mkdir .deepagents: %v", err)
	}

	if got := detectAgentHarness(dir); got != "deepagents-cli" {
		t.Fatalf("detectAgentHarness() = %q, want deepagents-cli", got)
	}
}

func TestDetectAgentHarness_NoMarkerDoesNotAssumeBinary(t *testing.T) {
	dir := t.TempDir()
	if got := detectAgentHarness(dir); got == "openclaw" || got == "deepagents-cli" {
		t.Fatalf("detectAgentHarness() returned %q without marker directory", got)
	}
}
