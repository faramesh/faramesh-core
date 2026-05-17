package mcp

import (
	"encoding/json"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core"
)

// taskCompleteParams is the faramesh/tasks/complete extension (async MCP Task governance).
type taskCompleteParams struct {
	TaskID          string `json:"task_id"`
	SessionID       string `json:"session_id"`
	AgentID         string `json:"agent_id,omitempty"`
	ResultSummary   string `json:"result_summary,omitempty"`
	ReasoningSummary string `json:"reasoning_summary,omitempty"`
}

func (g *StdioGateway) evaluateTaskCompletion(msg MCPMessage) (MCPMessage, error) {
	var params taskCompleteParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return errorResponse(msg.ID, -32602, "invalid params: "+err.Error()), nil
	}
	taskID := strings.TrimSpace(params.TaskID)
	if taskID == "" {
		return errorResponse(msg.ID, -32602, "missing task_id"), nil
	}
	agentID := strings.TrimSpace(params.AgentID)
	if agentID == "" {
		agentID = g.agentID
	}
	sessionID := strings.TrimSpace(params.SessionID)
	if sessionID == "" {
		sessionID = "mcp-task"
	}
	req := core.CanonicalActionRequest{
		CallID:           "mcp-task-complete-" + taskID,
		AgentID:          agentID,
		SessionID:        sessionID,
		ToolID:           "mcp/task.complete",
		ActionType:       core.ActionTypeCompletionEvent,
		Args:             map[string]any{"task_id": taskID},
		ReasoningSummary: params.ReasoningSummary,
		InterceptAdapter: "mcp",
	}
	if params.ResultSummary != "" {
		req.Args["result_summary"] = params.ResultSummary
	}
	dec := g.pipeline.Evaluate(req)
	result, _ := json.Marshal(map[string]any{
		"task_id":     taskID,
		"effect":      string(dec.Effect),
		"reason_code": dec.ReasonCode,
		"record_id":   dec.DPRRecordID,
	})
	return MCPMessage{JSONRPC: "2.0", ID: msg.ID, Result: result}, nil
}
