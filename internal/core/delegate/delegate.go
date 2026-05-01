// Package delegate provides persistent agent-to-agent delegation grants
// backing the `faramesh delegate` CLI surface.
//
// A Grant authorises one agent (FromAgent) to act on behalf of another
// (ToAgent) for a bounded scope, time window, and chain depth. Tokens
// issued for a grant are HMAC-signed so they can be verified offline and
// rejected on tamper. The store also tracks revocation and is the source
// of truth for chain reconstruction.
package delegate

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Grant is a persisted delegation record.
type Grant struct {
	Token      string    `json:"token"`
	FromAgent  string    `json:"from_agent"`
	ToAgent    string    `json:"to_agent"`
	Scope      string    `json:"scope"`
	Ceiling    string    `json:"ceiling,omitempty"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	ChainDepth int       `json:"chain_depth"`
	Active     bool      `json:"active"`
}

// IsValidAt returns true if the grant is currently active and unexpired.
func (g *Grant) IsValidAt(now time.Time) bool {
	return g != nil && g.Active && now.Before(g.ExpiresAt)
}

// Store is the persistence interface for delegation grants.
//
// Implementations must be safe for concurrent use.
type Store interface {
	Insert(g Grant) error
	GetByToken(token string) (Grant, bool)
	ListByAgent(agentID string) []Grant
	ListInbound(agentID string) []Grant
	Revoke(from, to string) (int, error)
}

// ErrDuplicateToken is returned when a token already exists in the store.
var ErrDuplicateToken = errors.New("delegate: duplicate token")

// MemoryStore is an in-memory Store backed by a map keyed by token.
type MemoryStore struct {
	mu     sync.RWMutex
	grants map[string]Grant
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{grants: make(map[string]Grant)}
}

func (s *MemoryStore) Insert(g Grant) error {
	if strings.TrimSpace(g.Token) == "" {
		return fmt.Errorf("delegate: insert requires non-empty token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[g.Token]; exists {
		return ErrDuplicateToken
	}
	s.grants[g.Token] = g
	return nil
}

func (s *MemoryStore) GetByToken(token string) (Grant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[token]
	return g, ok
}

// ListByAgent returns grants where the agent is either the from-agent or
// the to-agent, sorted newest-first.
func (s *MemoryStore) ListByAgent(agentID string) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Grant
	for _, g := range s.grants {
		if g.FromAgent == agentID || g.ToAgent == agentID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IssuedAt.After(out[j].IssuedAt)
	})
	return out
}

// ListInbound returns active grants where agentID is the to-agent. Used for
// chain depth and scope-subset checks at grant time.
func (s *MemoryStore) ListInbound(agentID string) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Grant
	for _, g := range s.grants {
		if g.ToAgent == agentID && g.Active {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IssuedAt.After(out[j].IssuedAt)
	})
	return out
}

// Revoke marks all active grants from→to as inactive and returns the count
// updated.
func (s *MemoryStore) Revoke(from, to string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for tok, g := range s.grants {
		if g.FromAgent == from && g.ToAgent == to && g.Active {
			g.Active = false
			s.grants[tok] = g
			n++
		}
	}
	return n, nil
}
