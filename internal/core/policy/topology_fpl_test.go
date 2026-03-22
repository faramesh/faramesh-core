package policy

import "testing"

func TestMergeOrchestratorManifestFromFPL_inline(t *testing.T) {
	yaml := `
faramesh-version: "1.0"
agent-id: "orch-1"
default_effect: deny
fpl_inline: |
  manifest orchestrator orch-1 undeclared deny
  manifest grant orch-1 to worker-a max 10
rules:
  - id: allow-invoke
    match: { tool: "multiagent/invoke_agent" }
    effect: permit
`
	doc, _, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if doc.OrchestratorManifest == nil {
		t.Fatal()
	}
	if doc.OrchestratorManifest.AgentID != "orch-1" {
		t.Fatalf("%q", doc.OrchestratorManifest.AgentID)
	}
	if doc.OrchestratorManifest.UndeclaredInvocationPolicy != "deny" {
		t.Fatalf("%q", doc.OrchestratorManifest.UndeclaredInvocationPolicy)
	}
	if len(doc.OrchestratorManifest.PermittedInvocations) != 1 {
		t.Fatalf("%+v", doc.OrchestratorManifest.PermittedInvocations)
	}
	inv := doc.OrchestratorManifest.PermittedInvocations[0]
	if inv.AgentID != "worker-a" || inv.MaxInvocationsPerSession != 10 || inv.RequiresPriorApproval {
		t.Fatalf("%+v", inv)
	}
}

func TestMergeOrchestratorManifestFromFPL_overridesYAMLCap(t *testing.T) {
	yaml := `
faramesh-version: "1.0"
agent-id: "orch-1"
default_effect: deny
orchestrator_manifest:
  agent_id: "orch-1"
  undeclared_invocation_policy: deny
  permitted_invocations:
    - agent_id: "worker-a"
      max_invocations_per_session: 3
fpl_inline: |
  manifest grant orch-1 to worker-a max 99
rules: []
`
	doc, _, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, inv := range doc.OrchestratorManifest.PermittedInvocations {
		if inv.AgentID == "worker-a" {
			found = true
			if inv.MaxInvocationsPerSession != 99 {
				t.Fatalf("expected FPL override 99, got %d", inv.MaxInvocationsPerSession)
			}
		}
	}
	if !found {
		t.Fatal("worker-a missing")
	}
}

func TestMergeOrchestratorManifestFromFPL_yamlOrchConflict(t *testing.T) {
	yaml := `
faramesh-version: "1.0"
agent-id: "x"
default_effect: deny
orchestrator_manifest:
  agent_id: "orch-yaml"
  permitted_invocations: []
fpl_inline: |
  manifest grant orch-fpl to a max 1
rules: []
`
	_, _, err := LoadBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error")
	}
}
