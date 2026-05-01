package fpl

import "testing"

func TestParseProgram_topologyLines(t *testing.T) {
	src := `
manifest orchestrator orch-1 undeclared deny
manifest grant orch-1 to worker-a max 10
manifest grant orch-1 to worker-b max 0 approval
permit multiagent/invoke_agent when true
`
	p, err := ParseProgram(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 1 || p.Rules[0].Tool != "multiagent/invoke_agent" {
		t.Fatalf("rules: %+v", p.Rules)
	}
	if len(p.Topo) != 3 {
		t.Fatalf("topo len %d", len(p.Topo))
	}
	if p.Topo[0].Kind != TopoOrchestrator || p.Topo[0].OrchID != "orch-1" || p.Topo[0].UndeclaredPolicy != "deny" {
		t.Fatalf("decl: %+v", p.Topo[0])
	}
	if p.Topo[1].Kind != TopoAllow || p.Topo[1].TargetAgentID != "worker-a" || p.Topo[1].MaxPerSession != 10 || p.Topo[1].RequiresApproval {
		t.Fatalf("allow a: %+v", p.Topo[1])
	}
	if p.Topo[2].Kind != TopoAllow || p.Topo[2].TargetAgentID != "worker-b" || p.Topo[2].MaxPerSession != 0 || !p.Topo[2].RequiresApproval {
		t.Fatalf("allow b: %+v", p.Topo[2])
	}
}

func TestParseProgram_yamlIndentedFPL(t *testing.T) {
	s := "  manifest orchestrator orch-1 undeclared deny\n  manifest grant orch-1 to worker-a max 10\n"
	if _, err := ParseProgram(s); err != nil {
		t.Fatal(err)
	}
}
