package sdk

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/standing"
)

type standingGrantAddRequest struct {
	AdminToken    string `json:"admin_token"`
	AgentID       string `json:"agent_id"`
	SessionID     string `json:"session_id"`
	ToolPattern   string `json:"tool_pattern"`
	PolicyVersion string `json:"policy_version"`
	RuleID        string `json:"rule_id"`
	TTLSeconds    int    `json:"ttl_seconds"`
	MaxUses       int    `json:"max_uses"`
	IssuedBy      string `json:"issued_by"`
}

type standingGrantRevokeRequest struct {
	AdminToken string `json:"admin_token"`
	GrantID    string `json:"grant_id"`
}

type standingGrantListRequest struct {
	AdminToken string `json:"admin_token"`
}

func (s *Server) authorizeStandingAdmin(conn net.Conn, got string) bool {
	want := s.standingAdminToken
	if want == "" {
		writeJSON(conn, map[string]any{"error": "standing_grants_admin_unconfigured: set daemon --standing-admin-token, FARAMESH_STANDING_ADMIN_TOKEN, or --policy-admin-token / FARAMESH_POLICY_ADMIN_TOKEN"})
		return false
	}
	if len(got) != len(want) {
		writeJSON(conn, map[string]any{"error": "unauthorized standing admin request"})
		return false
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(conn, map[string]any{"error": "unauthorized standing admin request"})
		return false
	}
	return true
}

func (s *Server) authorizeControlAdmin(conn net.Conn, got string) bool {
	want := s.standingAdminToken
	if want == "" {
		writeJSON(conn, map[string]any{"error": "control_admin_unconfigured: set daemon --standing-admin-token, FARAMESH_STANDING_ADMIN_TOKEN, or --policy-admin-token / FARAMESH_POLICY_ADMIN_TOKEN"})
		return false
	}
	if len(got) != len(want) {
		writeJSON(conn, map[string]any{"error": "unauthorized control admin request"})
		return false
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeJSON(conn, map[string]any{"error": "unauthorized control admin request"})
		return false
	}
	return true
}

func (s *Server) handleStandingGrantAdd(conn net.Conn, line []byte) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}
	var req standingGrantAddRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid standing_grant_add request"})
		return
	}
	if !s.authorizeStandingAdmin(conn, strings.TrimSpace(req.AdminToken)) {
		return
	}
	if req.TTLSeconds <= 0 {
		writeJSON(conn, map[string]any{"error": "ttl_seconds must be > 0"})
		return
	}
	g, err := s.pipeline.RegisterStandingGrant(standing.Input{
		AgentID:       req.AgentID,
		SessionID:     req.SessionID,
		ToolPattern:   req.ToolPattern,
		PolicyVersion: req.PolicyVersion,
		RuleID:        req.RuleID,
		TTL:           time.Duration(req.TTLSeconds) * time.Second,
		MaxUses:       req.MaxUses,
		IssuedBy:      req.IssuedBy,
	})
	if err != nil {
		writeJSON(conn, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(conn, map[string]any{"ok": true, "grant": g})
}

func (s *Server) handleStandingGrantRevoke(conn net.Conn, line []byte) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}
	var req standingGrantRevokeRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid standing_grant_revoke request"})
		return
	}
	if !s.authorizeStandingAdmin(conn, strings.TrimSpace(req.AdminToken)) {
		return
	}
	id := strings.TrimSpace(req.GrantID)
	if id == "" {
		writeJSON(conn, map[string]any{"error": "grant_id is required"})
		return
	}
	ok, err := s.pipeline.RevokeStandingGrant(id)
	if err != nil {
		writeJSON(conn, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(conn, map[string]any{"ok": ok})
}

func (s *Server) handleStandingGrantList(conn net.Conn, line []byte) {
	if s.pipeline == nil {
		writeJSON(conn, map[string]any{"error": "pipeline unavailable"})
		return
	}
	var req standingGrantListRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid standing_grant_list request"})
		return
	}
	if !s.authorizeStandingAdmin(conn, strings.TrimSpace(req.AdminToken)) {
		return
	}
	grants := s.pipeline.ListStandingGrants()
	writeJSON(conn, map[string]any{"ok": true, "grants": grants})
}
