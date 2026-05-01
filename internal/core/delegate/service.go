package delegate

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultMaxDepth caps how long a delegation chain can grow. The README
// promises that "the supervisor's permissions are the ceiling for any
// sub-agent" — bounding depth is the simplest mechanical guard against
// runaway chains regardless of scope width.
const DefaultMaxDepth = 5

// Clock returns the current time. Injectable for tests.
type Clock func() time.Time

// Service orchestrates delegation grants on top of a Store.
type Service struct {
	store    Store
	signKey  []byte
	maxDepth int
	now      Clock
}

// NewService wires a service. signKey is typically DeriveKey(dprKey).
// If maxDepth is <= 0, DefaultMaxDepth is used.
func NewService(store Store, signKey []byte, maxDepth int, clock Clock) *Service {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{store: store, signKey: signKey, maxDepth: maxDepth, now: clock}
}

// GrantRequest mirrors the CLI's JSON body for /api/v1/delegate/grant.
type GrantRequest struct {
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	Scope     string `json:"scope"`
	TTL       string `json:"ttl"`
	Ceiling   string `json:"ceiling,omitempty"`
}

// GrantErrors surfaced by Service.Grant.
var (
	ErrInvalidRequest = errors.New("delegate: invalid request")
	ErrChainTooDeep   = errors.New("delegate: chain would exceed max depth")
	ErrScopeNotSubset = errors.New("delegate: scope is not a subset of parent scope")
)

// Grant validates the request, derives the chain depth from any inbound
// grants on the from-agent, signs and persists the new grant.
func (s *Service) Grant(req GrantRequest) (Grant, error) {
	from := strings.TrimSpace(req.FromAgent)
	to := strings.TrimSpace(req.ToAgent)
	scope := strings.TrimSpace(req.Scope)
	if from == "" || to == "" {
		return Grant{}, fmt.Errorf("%w: from_agent and to_agent are required", ErrInvalidRequest)
	}
	if from == to {
		return Grant{}, fmt.Errorf("%w: from_agent and to_agent must differ", ErrInvalidRequest)
	}
	if scope == "" {
		scope = "*"
	}
	ttl, err := parseTTL(req.TTL)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: ttl: %v", ErrInvalidRequest, err)
	}

	parent, hasParent := s.pickParent(from)
	depth := 1
	if hasParent {
		depth = parent.ChainDepth + 1
		if depth > s.maxDepth {
			return Grant{}, fmt.Errorf("%w: depth %d > max %d", ErrChainTooDeep, depth, s.maxDepth)
		}
		if !scopeIsSubset(scope, parent.Scope) {
			return Grant{}, fmt.Errorf("%w: %q not within %q", ErrScopeNotSubset, scope, parent.Scope)
		}
	}

	now := s.now().UTC()
	g := Grant{
		FromAgent:  from,
		ToAgent:    to,
		Scope:      scope,
		Ceiling:    strings.TrimSpace(req.Ceiling),
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
		ChainDepth: depth,
		Active:     true,
	}
	tok, err := Issue(g, s.signKey)
	if err != nil {
		return Grant{}, err
	}
	g.Token = tok
	if err := s.store.Insert(g); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// pickParent returns the most-recent active inbound grant on agent, used as
// the parent for chain depth and scope-subset checks.
func (s *Service) pickParent(agent string) (Grant, bool) {
	inbound := s.store.ListInbound(agent)
	now := s.now()
	for _, g := range inbound {
		if g.IsValidAt(now) {
			return g, true
		}
	}
	return Grant{}, false
}

// List returns grants involving agentID (as either side), newest-first.
func (s *Service) List(agentID string) []Grant {
	return s.store.ListByAgent(strings.TrimSpace(agentID))
}

// Inspect returns the stored grant matching the token, regardless of
// active/expired status. Returns false if not found.
func (s *Service) Inspect(token string) (Grant, bool) {
	g, ok := s.store.GetByToken(strings.TrimSpace(token))
	return g, ok
}

// VerifyResult is the structured outcome of a token verification.
type VerifyResult struct {
	Valid      bool      `json:"valid"`
	Reason     string    `json:"reason,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
	ChainDepth int       `json:"chain_depth,omitempty"`
}

// Verify checks signature, store presence, expiry, and revocation. The
// signature check (Parse) is performed first so a tampered token never
// hits the store.
func (s *Service) Verify(token string) VerifyResult {
	parsed, err := Parse(strings.TrimSpace(token), s.signKey)
	if err != nil {
		return VerifyResult{Valid: false, Reason: "invalid signature"}
	}
	stored, ok := s.store.GetByToken(parsed.Token)
	if !ok {
		return VerifyResult{Valid: false, Reason: "token not found"}
	}
	if !stored.Active {
		return VerifyResult{Valid: false, Reason: "revoked"}
	}
	if !s.now().Before(stored.ExpiresAt) {
		return VerifyResult{Valid: false, Reason: "expired"}
	}
	return VerifyResult{
		Valid:      true,
		Scope:      stored.Scope,
		ExpiresAt:  stored.ExpiresAt,
		ChainDepth: stored.ChainDepth,
	}
}

// Revoke marks any active grants from→to as inactive.
func (s *Service) Revoke(from, to string) (int, error) {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if from == "" || to == "" {
		return 0, fmt.Errorf("%w: from_agent and to_agent are required", ErrInvalidRequest)
	}
	return s.store.Revoke(from, to)
}

// Chain reconstructs the delegation chain ending at agentID, ordered from
// root to leaf. Walking stops at a cycle or when no inbound active grant
// exists. Cycle detection is by visited set on the from-agent.
func (s *Service) Chain(agentID string) []Grant {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil
	}
	visited := make(map[string]struct{})
	cursor := agentID
	var reverse []Grant
	for {
		if _, seen := visited[cursor]; seen {
			break
		}
		visited[cursor] = struct{}{}
		parent, ok := s.pickParent(cursor)
		if !ok {
			break
		}
		reverse = append(reverse, parent)
		cursor = parent.FromAgent
	}
	// Reverse to root→leaf order.
	out := make([]Grant, len(reverse))
	for i := range reverse {
		out[i] = reverse[len(reverse)-1-i]
	}
	return out
}

func parseTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl must be positive")
	}
	return d, nil
}

// scopeIsSubset reports whether child's scope is contained in parent's.
// Patterns support a trailing "*" glob; "*" alone is the universe.
// Multiple alternatives can be comma- or space-separated.
func scopeIsSubset(child, parent string) bool {
	if parent == "" || parent == "*" {
		return true
	}
	parents := splitScope(parent)
	for _, c := range splitScope(child) {
		matched := false
		for _, p := range parents {
			if scopeContains(p, c) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func splitScope(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// scopeContains reports whether parent matches everything child matches.
// Supports trailing-wildcard globs only; that matches the FPL convention
// used elsewhere in the codebase.
func scopeContains(parent, child string) bool {
	if parent == "*" {
		return true
	}
	if strings.HasSuffix(parent, "*") {
		prefix := strings.TrimSuffix(parent, "*")
		// Child must also be a subset of parent's prefix.
		if strings.HasSuffix(child, "*") {
			childPrefix := strings.TrimSuffix(child, "*")
			return strings.HasPrefix(childPrefix, prefix)
		}
		return strings.HasPrefix(child, prefix)
	}
	// Exact match required when parent has no wildcard.
	return parent == child
}
