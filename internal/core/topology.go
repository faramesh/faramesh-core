package core

import "strings"

// topologyInvokeTool identifies governed multi-agent delegation calls that must
// satisfy orchestrator routing manifests when policy defines orchestrator_manifest.
func topologyInvokeTool(toolID string) bool {
	if toolID == "multiagent/invoke_agent" || toolID == "invoke_agent" {
		return true
	}
	return strings.HasSuffix(toolID, "/invoke_agent")
}

// extractTargetAgentID reads the callee agent id from common CAR shapes.
func extractTargetAgentID(args map[string]any) string {
	if args == nil {
		return ""
	}
	if s, ok := args["target_agent_id"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	if s, ok := args["agent_id"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	if m, ok := args["params"].(map[string]any); ok {
		if s, ok := m["target_agent_id"].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
		if s, ok := m["agent_id"].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
