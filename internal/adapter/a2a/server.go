// Package a2a implements governed Agent-to-Agent proxying (FARAMESH.md tier 4).
package a2a

import (
	"encoding/json"
	"net/http"

	"github.com/faramesh/faramesh-core/internal/core"
)

// Server exposes Agent Card and governed delegation endpoints.
type Server struct {
	Pipeline *core.Pipeline
	AgentID  string
}

// NewServer creates an A2A governance HTTP handler.
func NewServer(pipeline *core.Pipeline, agentID string) *Server {
	return &Server{Pipeline: pipeline, AgentID: agentID}
}

// AgentCard serves /.well-known/agent-card.json with policy-permitted capabilities.
func (s *Server) AgentCard(w http.ResponseWriter, _ *http.Request) {
	card := map[string]any{
		"name":         s.AgentID,
		"description":  "Faramesh-governed agent",
		"capabilities": []string{"tool_call", "agent_delegation"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(card)
}

// Register mounts routes on mux.
func (s *Server) Register(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	mux.HandleFunc("/.well-known/agent-card.json", s.AgentCard)
	mux.HandleFunc("/v1/delegate", s.Delegate)
}
