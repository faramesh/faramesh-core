package core

import "testing"

func TestExtractTargetAgentID(t *testing.T) {
	if got := extractTargetAgentID(map[string]any{"target_agent_id": " x "}); got != "x" {
		t.Fatalf("got %q", got)
	}
	if got := extractTargetAgentID(map[string]any{"params": map[string]any{"agent_id": "p1"}}); got != "p1" {
		t.Fatalf("got %q", got)
	}
}

func TestTopologyInvokeTool(t *testing.T) {
	if !topologyInvokeTool("multiagent/invoke_agent") {
		t.Fatal()
	}
	if topologyInvokeTool("stripe/charge") {
		t.Fatal()
	}
}
