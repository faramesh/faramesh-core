package sdk

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/faramesh/faramesh-core/internal/daemon/agentsupervisor"
)

type supervisorLaunchRequest struct {
	Type    string   `json:"type"`
	AgentID string   `json:"agent_id"`
	Argv    []string `json:"argv"`
	Command string   `json:"command"`
}

func (s *Server) SetAgentSupervisor(sup *agentsupervisor.Supervisor) {
	s.supervisor = sup
}

func (s *Server) handleSupervisorLaunch(conn net.Conn, line []byte) {
	if s.supervisor == nil {
		writeJSON(conn, map[string]any{"error": "agent supervisor not enabled"})
		return
	}
	var req supervisorLaunchRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid JSON"})
		return
	}
	argv := req.Argv
	if len(argv) == 0 && strings.TrimSpace(req.Command) != "" {
		argv = strings.Fields(req.Command)
	}
	proc, err := s.supervisor.Launch(context.Background(), req.AgentID, argv)
	if err != nil {
		writeJSON(conn, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(conn, map[string]any{"ok": true, "process": proc})
}

func (s *Server) handleSupervisorStop(conn net.Conn, line []byte) {
	if s.supervisor == nil {
		writeJSON(conn, map[string]any{"error": "agent supervisor not enabled"})
		return
	}
	var req struct {
		AgentID string `json:"agent_id"`
	}
	_ = json.Unmarshal(line, &req)
	if err := s.supervisor.Stop(req.AgentID); err != nil {
		writeJSON(conn, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(conn, map[string]any{"ok": true})
}

func (s *Server) handleSupervisorList(conn net.Conn) {
	if s.supervisor == nil {
		writeJSON(conn, map[string]any{"processes": []agentsupervisor.Process{}})
		return
	}
	writeJSON(conn, map[string]any{"processes": s.supervisor.List()})
}
