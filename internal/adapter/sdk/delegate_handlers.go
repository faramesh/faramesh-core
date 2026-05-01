package sdk

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/delegate"
)

// delegateRequest is the umbrella shape for every "type":"delegate" socket
// message. The op field selects the sub-operation; the rest of the payload
// is op-specific.
type delegateRequest struct {
	AdminToken string `json:"admin_token"`
	Op         string `json:"op"`

	// Grant fields.
	FromAgent string `json:"from_agent,omitempty"`
	ToAgent   string `json:"to_agent,omitempty"`
	Scope     string `json:"scope,omitempty"`
	TTL       string `json:"ttl,omitempty"`
	Ceiling   string `json:"ceiling,omitempty"`

	// Lookup fields.
	AgentID string `json:"agent_id,omitempty"`
	Token   string `json:"token,omitempty"`
}

// handleDelegate dispatches every "type":"delegate" socket message. All
// operations require the daemon's configured admin token — grants are a
// security-relevant control surface, including reads (which expose who has
// authority over whom).
func (s *Server) handleDelegate(conn net.Conn, line []byte) {
	if s.delegate == nil {
		writeJSON(conn, map[string]any{"error": "delegate service unavailable"})
		return
	}
	var req delegateRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid delegate request"})
		return
	}
	if !s.authorizeControlAdmin(conn, strings.TrimSpace(req.AdminToken)) {
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Op)) {
	case "grant":
		s.handleDelegateGrant(conn, req)
	case "list":
		s.handleDelegateList(conn, req)
	case "revoke":
		s.handleDelegateRevoke(conn, req)
	case "inspect":
		s.handleDelegateInspect(conn, req)
	case "verify":
		s.handleDelegateVerify(conn, req)
	case "chain":
		s.handleDelegateChain(conn, req)
	case "":
		writeJSON(conn, map[string]any{"error": "delegate op is required"})
	default:
		writeJSON(conn, map[string]any{"error": "unknown delegate op: " + req.Op})
	}
}

func (s *Server) handleDelegateGrant(conn net.Conn, req delegateRequest) {
	g, err := s.delegate.Grant(delegate.GrantRequest{
		FromAgent: req.FromAgent,
		ToAgent:   req.ToAgent,
		Scope:     req.Scope,
		TTL:       req.TTL,
		Ceiling:   req.Ceiling,
	})
	if err != nil {
		writeJSON(conn, map[string]any{"error": err.Error(), "category": delegateErrCategory(err)})
		return
	}
	writeJSON(conn, map[string]any{
		"token":      g.Token,
		"from_agent": g.FromAgent,
		"to_agent":   g.ToAgent,
		"scope":      g.Scope,
		"expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
		"ceiling":    g.Ceiling,
	})
}

func (s *Server) handleDelegateList(conn net.Conn, req delegateRequest) {
	if strings.TrimSpace(req.AgentID) == "" {
		writeJSON(conn, map[string]any{"error": "agent_id is required"})
		return
	}
	grants := s.delegate.List(req.AgentID)
	out := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		out = append(out, grantToMap(g))
	}
	writeJSON(conn, map[string]any{"delegations": out})
}

func (s *Server) handleDelegateRevoke(conn net.Conn, req delegateRequest) {
	n, err := s.delegate.Revoke(req.FromAgent, req.ToAgent)
	if err != nil {
		writeJSON(conn, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{"revoked": n > 0}
	if n == 0 {
		resp["message"] = "no active delegations found"
	} else {
		resp["message"] = "revoked"
		resp["count"] = n
	}
	writeJSON(conn, resp)
}

func (s *Server) handleDelegateInspect(conn net.Conn, req delegateRequest) {
	if strings.TrimSpace(req.Token) == "" {
		writeJSON(conn, map[string]any{"error": "token is required"})
		return
	}
	g, ok := s.delegate.Inspect(req.Token)
	if !ok {
		writeJSON(conn, map[string]any{"error": "token not found"})
		return
	}
	writeJSON(conn, grantToMap(g))
}

func (s *Server) handleDelegateVerify(conn net.Conn, req delegateRequest) {
	res := s.delegate.Verify(req.Token)
	out := map[string]any{
		"valid":       res.Valid,
		"reason":      res.Reason,
		"scope":       res.Scope,
		"chain_depth": res.ChainDepth,
	}
	if !res.ExpiresAt.IsZero() {
		out["expires_at"] = res.ExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(conn, out)
}

func (s *Server) handleDelegateChain(conn net.Conn, req delegateRequest) {
	if strings.TrimSpace(req.AgentID) == "" {
		writeJSON(conn, map[string]any{"error": "agent_id is required"})
		return
	}
	chain := s.delegate.Chain(req.AgentID)
	links := make([]map[string]any, 0, len(chain))
	for _, g := range chain {
		links = append(links, map[string]any{
			"from_agent": g.FromAgent,
			"to_agent":   g.ToAgent,
			"scope":      g.Scope,
			"expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
			"depth":      g.ChainDepth,
		})
	}
	writeJSON(conn, map[string]any{"agent_id": req.AgentID, "chain": links})
}

func grantToMap(g delegate.Grant) map[string]any {
	return map[string]any{
		"token":       g.Token,
		"from_agent":  g.FromAgent,
		"to_agent":    g.ToAgent,
		"scope":       g.Scope,
		"ceiling":     g.Ceiling,
		"expires_at":  g.ExpiresAt.UTC().Format(time.RFC3339),
		"created_at":  g.IssuedAt.UTC().Format(time.RFC3339),
		"chain_depth": g.ChainDepth,
		"active":      g.Active,
	}
}

func delegateErrCategory(err error) string {
	switch {
	case errors.Is(err, delegate.ErrChainTooDeep):
		return "chain_too_deep"
	case errors.Is(err, delegate.ErrScopeNotSubset):
		return "scope_not_subset"
	case errors.Is(err, delegate.ErrInvalidRequest):
		return "invalid_request"
	default:
		return "internal"
	}
}
