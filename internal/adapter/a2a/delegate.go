package a2a

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core"
)

// Delegate handles inbound A2A task delegation through the governance pipeline.
func (s *Server) Delegate(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.Pipeline == nil {
		http.Error(w, "governance unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var payload struct {
		TaskID    string         `json:"task_id"`
		SessionID string         `json:"session_id"`
		ToolID    string         `json:"tool_id"`
		Args      map[string]any `json:"args"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	toolID := strings.TrimSpace(payload.ToolID)
	if toolID == "" {
		toolID = "a2a/delegate"
	}
	agentID := s.AgentID
	if agentID == "" {
		agentID = "default"
	}
	decision := s.Pipeline.Evaluate(core.CanonicalActionRequest{
		AgentID:     agentID,
		SessionID:   payload.SessionID,
		ToolID:      toolID,
		Args:        payload.Args,
		ActionType:  core.ActionTypeInboundDelegation,
		CallID: payload.TaskID,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"effect":     decision.Effect,
		"reason":     decision.Reason,
		"reason_code": decision.ReasonCode,
		"record_id":  decision.DPRRecordID,
	})
}
