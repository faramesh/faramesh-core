package core

import (
	"testing"
	"time"
)

func TestExtractTargetAgentID(t *testing.T) {
	if got := extractTargetAgentID(map[string]any{"target_agent_id": " x "}); got != "x" {
		t.Fatalf("got %q", got)
	}
	if got := extractTargetAgentID(map[string]any{"params": map[string]any{"agent_id": "p1"}}); got != "p1" {
		t.Fatalf("got %q", got)
	}
	if got := extractTargetAgentID(map[string]any{"input": map[string]any{"target_agent_id": "worker-a"}}); got != "worker-a" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractDelegationConstraintsFromNestedInput(t *testing.T) {
	if got := extractDelegationScope(map[string]any{"input": map[string]any{"delegation_scope": "safe/read"}}); got != "safe/read" {
		t.Fatalf("scope got %q", got)
	}
	if ttl, ok := extractDelegationTTL(map[string]any{"input": map[string]any{"delegation_ttl": "30m"}}); !ok || ttl != 30*time.Minute {
		t.Fatalf("ttl = %v, %v", ttl, ok)
	}
}

func TestTopologyInvokeTool(t *testing.T) {
	if !topologyInvokeTool("multiagent/invoke_agent") {
		t.Fatal()
	}
	if !topologyInvokeTool("multiagent/invoke_agent/_run_one") {
		t.Fatal()
	}
	if !topologyInvokeTool("multiagent/invoke_agent/_execute_tool_sync") {
		t.Fatal()
	}
	if topologyInvokeTool("stripe/charge") {
		t.Fatal()
	}
}
