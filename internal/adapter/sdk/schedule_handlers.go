package sdk

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/schedule"
)

// scheduleRequest is the umbrella shape for every "type":"schedule"
// socket message. The op field selects the sub-operation.
type scheduleRequest struct {
	AdminToken string `json:"admin_token"`
	Op         string `json:"op"`

	// Create fields.
	Tool   string `json:"tool,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Args   string `json:"args,omitempty"`
	At     string `json:"at,omitempty"`
	Policy string `json:"policy,omitempty"`
	Reeval bool   `json:"reeval,omitempty"`

	// Lookup / mutation fields.
	ID         string `json:"id,omitempty"`
	ScheduleID string `json:"schedule_id,omitempty"`
	Approver   string `json:"approver,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	Window     string `json:"window,omitempty"`
}

func (r scheduleRequest) targetID() string {
	if id := strings.TrimSpace(r.ID); id != "" {
		return id
	}
	return strings.TrimSpace(r.ScheduleID)
}

// handleSchedule dispatches every "type":"schedule" socket message. All
// operations require the daemon's admin token — schedules are a
// security-relevant control surface, including reads which expose the
// agent's intended actions.
func (s *Server) handleSchedule(conn net.Conn, line []byte) {
	if s.schedule == nil {
		writeJSON(conn, map[string]any{"error": "schedule service unavailable"})
		return
	}
	var req scheduleRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid schedule request"})
		return
	}
	if !s.authorizeControlAdmin(conn, strings.TrimSpace(req.AdminToken)) {
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Op)) {
	case "create":
		s.handleScheduleCreate(conn, req)
	case "list":
		s.handleScheduleList(conn, req)
	case "inspect":
		s.handleScheduleInspect(conn, req)
	case "cancel":
		s.handleScheduleCancel(conn, req)
	case "approve":
		s.handleScheduleApprove(conn, req)
	case "pending":
		s.handleSchedulePending(conn, req)
	case "history":
		s.handleScheduleHistory(conn, req)
	case "":
		writeJSON(conn, map[string]any{"error": "schedule op is required"})
	default:
		writeJSON(conn, map[string]any{"error": "unknown schedule op: " + req.Op})
	}
}

func (s *Server) handleScheduleCreate(conn net.Conn, req scheduleRequest) {
	e, err := s.schedule.Create(schedule.CreateRequest{
		Tool:   req.Tool,
		Agent:  req.Agent,
		Args:   req.Args,
		At:     req.At,
		Policy: req.Policy,
		Reeval: req.Reeval,
	})
	if err != nil {
		writeJSON(conn, map[string]any{
			"error":    err.Error(),
			"category": scheduleErrCategory(err),
		})
		return
	}
	writeJSON(conn, executionToMap(e))
}

func (s *Server) handleScheduleList(conn net.Conn, req scheduleRequest) {
	agentID := strings.TrimSpace(req.AgentID)
	if agentID == "" {
		agentID = strings.TrimSpace(req.Agent)
	}
	entries := s.schedule.List(agentID)
	writeJSON(conn, map[string]any{"schedules": executionsToMaps(entries)})
}

func (s *Server) handleScheduleInspect(conn net.Conn, req scheduleRequest) {
	id := req.targetID()
	if id == "" {
		writeJSON(conn, map[string]any{"error": "id is required"})
		return
	}
	e, ok := s.schedule.Inspect(id)
	if !ok {
		writeJSON(conn, map[string]any{"error": "schedule not found"})
		return
	}
	writeJSON(conn, executionToMap(e))
}

func (s *Server) handleScheduleCancel(conn net.Conn, req scheduleRequest) {
	id := req.targetID()
	if id == "" {
		writeJSON(conn, map[string]any{"error": "schedule_id is required"})
		return
	}
	e, err := s.schedule.Cancel(id)
	if err != nil {
		writeJSON(conn, scheduleMutationError(err))
		return
	}
	writeJSON(conn, executionToMap(e))
}

func (s *Server) handleScheduleApprove(conn net.Conn, req scheduleRequest) {
	id := req.targetID()
	if id == "" {
		writeJSON(conn, map[string]any{"error": "schedule_id is required"})
		return
	}
	e, err := s.schedule.Approve(id, req.Approver)
	if err != nil {
		writeJSON(conn, scheduleMutationError(err))
		return
	}
	writeJSON(conn, executionToMap(e))
}

func (s *Server) handleSchedulePending(conn net.Conn, _ scheduleRequest) {
	entries := s.schedule.Pending()
	writeJSON(conn, map[string]any{"pending": executionsToMaps(entries)})
}

func (s *Server) handleScheduleHistory(conn net.Conn, req scheduleRequest) {
	window := 24 * time.Hour
	if w := strings.TrimSpace(req.Window); w != "" {
		if d, err := time.ParseDuration(w); err == nil && d > 0 {
			window = d
		}
	}
	entries := s.schedule.History(window)
	writeJSON(conn, map[string]any{"history": executionsToMaps(entries)})
}

func executionToMap(e schedule.ScheduledExecution) map[string]any {
	out := map[string]any{
		"id":             e.ID,
		"agent_id":       e.AgentID,
		"tool":           e.Tool,
		"args":           e.Args,
		"policy":         e.Policy,
		"reeval":         e.Reeval,
		"scheduled_at":   e.ScheduledAt.UTC().Format(time.RFC3339),
		"created_at":     e.CreatedAt.UTC().Format(time.RFC3339),
		"status":         string(e.Status),
		"status_message": e.StatusMessage,
	}
	if !e.ExecutedAt.IsZero() {
		out["executed_at"] = e.ExecutedAt.UTC().Format(time.RFC3339)
	}
	if !e.ApprovedAt.IsZero() {
		out["approved_at"] = e.ApprovedAt.UTC().Format(time.RFC3339)
	}
	if e.ApprovedBy != "" {
		out["approved_by"] = e.ApprovedBy
	}
	return out
}

func executionsToMaps(in []schedule.ScheduledExecution) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, e := range in {
		out = append(out, executionToMap(e))
	}
	return out
}

func scheduleErrCategory(err error) string {
	switch {
	case errors.Is(err, schedule.ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, schedule.ErrInvalidTime):
		return "invalid_time"
	case errors.Is(err, schedule.ErrInvalidStatus):
		return "invalid_status"
	case errors.Is(err, schedule.ErrNotFound):
		return "not_found"
	case errors.Is(err, schedule.ErrDuplicateID):
		return "duplicate_id"
	default:
		return "internal"
	}
}

func scheduleMutationError(err error) map[string]any {
	resp := map[string]any{"error": err.Error(), "category": scheduleErrCategory(err)}
	return resp
}
