// Package standing implements time- and scope-bounded pre-approvals that turn
// policy-matched DEFER into PERMIT without a per-call defer token workflow.
package standing

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Grant is a standing approval record. When the daemon uses OpenRegistryStore,
// grants persist across restarts in SQLite under the data directory.
type Grant struct {
	ID             string    `json:"id"`
	AgentID        string    `json:"agent_id"`
	SessionID      string    `json:"session_id,omitempty"`
	ToolPattern    string    `json:"tool_pattern"`
	PolicyVersion  string    `json:"policy_version,omitempty"`
	RuleID         string    `json:"rule_id,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	MaxUses        int       `json:"max_uses"`
	Uses           int       `json:"uses"`
	IssuedBy       string    `json:"issued_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// Input describes a new standing grant from an operator.
type Input struct {
	AgentID       string
	SessionID     string
	ToolPattern   string
	PolicyVersion string
	RuleID        string
	TTL           time.Duration
	MaxUses       int
	IssuedBy      string
}

// Registry stores standing grants. With db set (via OpenRegistryStore), all
// mutations are written through to SQLite.
type Registry struct {
	mu     sync.Mutex
	grants []*Grant
	db     *sql.DB
}

// NewRegistry returns an in-memory-only registry (tests and tools that do not
// open a daemon data directory).
func NewRegistry() *Registry {
	return &Registry{}
}

// Add validates input and appends a grant. TTL must be positive.
func (r *Registry) Add(in Input) (*Grant, error) {
	agent := strings.TrimSpace(in.AgentID)
	if agent == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	pat := strings.TrimSpace(in.ToolPattern)
	if pat == "" {
		return nil, fmt.Errorf("tool_pattern is required")
	}
	if in.TTL <= 0 || in.TTL > 30*24*time.Hour {
		return nil, fmt.Errorf("ttl must be between 1s and 720h")
	}
	if in.MaxUses < 0 {
		return nil, fmt.Errorf("max_uses cannot be negative")
	}
	by := strings.TrimSpace(in.IssuedBy)
	if by == "" {
		return nil, fmt.Errorf("issued_by is required")
	}
	id, err := newGrantID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	g := &Grant{
		ID:             id,
		AgentID:        agent,
		SessionID:      strings.TrimSpace(in.SessionID),
		ToolPattern:    pat,
		PolicyVersion:  strings.TrimSpace(in.PolicyVersion),
		RuleID:         strings.TrimSpace(in.RuleID),
		ExpiresAt:      now.Add(in.TTL),
		MaxUses:        in.MaxUses,
		IssuedBy:       by,
		CreatedAt:      now,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpiredLocked(now)
	r.grants = append(r.grants, g)
	if r.db != nil {
		if err := r.persistInsertGrant(g); err != nil {
			r.grants = r.grants[:len(r.grants)-1]
			return nil, err
		}
	}
	out := *g
	return &out, nil
}

// Revoke removes a grant by id. Returns (false, nil) if not found, or an
// error when the backing store fails to delete a persisted row.
func (r *Registry) Revoke(id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id = strings.TrimSpace(id)
	for i, g := range r.grants {
		if g != nil && g.ID == id {
			if r.db != nil {
				if err := r.persistDeleteGrant(id, true); err != nil {
					return false, err
				}
			}
			r.grants = append(r.grants[:i], r.grants[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

// List returns a shallow copy snapshot for APIs.
func (r *Registry) List() []Grant {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpiredLocked(time.Now().UTC())
	out := make([]Grant, 0, len(r.grants))
	for _, g := range r.grants {
		if g == nil {
			continue
		}
		out = append(out, *g)
	}
	return out
}

// TryConsume finds a matching grant, increments Uses if under MaxUses, and
// returns a copy of the grant used (for audit). Returns nil if none applied.
// Only policy-engine DEFER paths should call this (caller passes non-empty ruleID).
func (r *Registry) TryConsume(agentID, sessionID, toolID, policyVersion, ruleID string, now time.Time) *Grant {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneExpiredLocked(now)
	for i := 0; i < len(r.grants); i++ {
		g := r.grants[i]
		if g == nil {
			continue
		}
		if now.After(g.ExpiresAt) {
			continue
		}
		if g.AgentID != agentID {
			continue
		}
		if g.SessionID != "" && g.SessionID != sessionID {
			continue
		}
		if g.PolicyVersion != "" && g.PolicyVersion != policyVersion {
			continue
		}
		if g.RuleID != "" && g.RuleID != ruleID {
			continue
		}
		if !matchToolPattern(g.ToolPattern, toolID) {
			continue
		}
		if g.MaxUses > 0 && g.Uses >= g.MaxUses {
			continue
		}
		g.Uses++
		if r.db != nil {
			if g.MaxUses > 0 && g.Uses >= g.MaxUses {
				if err := r.persistDeleteGrant(g.ID, true); err != nil {
					g.Uses--
					return nil
				}
				r.grants = append(r.grants[:i], r.grants[i+1:]...)
			} else if err := r.persistUpdateUses(g.ID, g.Uses); err != nil {
				g.Uses--
				return nil
			}
		} else if g.MaxUses > 0 && g.Uses >= g.MaxUses {
			r.grants = append(r.grants[:i], r.grants[i+1:]...)
		}
		out := *g
		return &out
	}
	return nil
}

func (r *Registry) pruneExpiredLocked(now time.Time) {
	if r == nil {
		return
	}
	var kept []*Grant
	for _, g := range r.grants {
		if g == nil {
			continue
		}
		if !now.After(g.ExpiresAt) {
			kept = append(kept, g)
			continue
		}
		if r.db != nil {
			if err := r.persistDeleteGrant(g.ID, false); err != nil {
				kept = append(kept, g)
			}
		}
	}
	r.grants = kept
}

func newGrantID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("grant id: %w", err)
	}
	return "stg_" + hex.EncodeToString(b[:]), nil
}

// matchToolPattern mirrors internal/core/pipeline.matchToolPattern semantics.
func matchToolPattern(pattern, toolID string) bool {
	pattern = strings.TrimSpace(pattern)
	toolID = strings.TrimSpace(toolID)
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(toolID, prefix)
	}
	return toolID == pattern
}
