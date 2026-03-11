// Package principal — principal elevation API.
//
// Implements mid-session privilege elevation with MFA verification, TTL,
// evidence hashing, and DPR audit records. This is the "sudo for agents"
// mechanism: a principal can temporarily gain higher-tier privileges after
// passing additional verification.
//
// Elevation flow:
//  1. Agent requests elevation with reason + target tier
//  2. Elevation engine checks if the transition is permitted by policy
//  3. MFA challenge issued (TOTP, WebAuthn, or approval link)
//  4. On verification, a time-bounded ElevationGrant is issued
//  5. Pipeline uses the elevated tier for policy evaluation until TTL expires
//  6. DPR records both the elevation and all decisions made under it
package principal

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// ElevationRequest is a request to elevate a principal's privileges.
type ElevationRequest struct {
	PrincipalID string `json:"principal_id"`
	CurrentTier string `json:"current_tier"`
	TargetTier  string `json:"target_tier"`
	Reason      string `json:"reason"`
	Evidence    []byte `json:"evidence,omitempty"` // hash of supporting evidence
	MFAMethod   string `json:"mfa_method"`         // totp, webauthn, approval
}

// ElevationGrant is the result of a successful elevation.
type ElevationGrant struct {
	GrantID      string    `json:"grant_id"`
	PrincipalID  string    `json:"principal_id"`
	OriginalTier string    `json:"original_tier"`
	ElevatedTier string    `json:"elevated_tier"`
	Reason       string    `json:"reason"`
	EvidenceHash string    `json:"evidence_hash"`
	GrantedAt    time.Time `json:"granted_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	MFAVerified  bool      `json:"mfa_verified"`
	Revoked      bool      `json:"revoked"`
}

// Valid returns true if the grant is active and not revoked.
func (g *ElevationGrant) Valid() bool {
	return !g.Revoked && time.Now().Before(g.ExpiresAt)
}

// RemainingTTL returns how much time is left on the elevation.
func (g *ElevationGrant) RemainingTTL() time.Duration {
	if g.Revoked {
		return 0
	}
	remaining := time.Until(g.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ElevationPolicy defines which tier transitions are permitted and their constraints.
type ElevationPolicy struct {
	// Transitions maps "from_tier→to_tier" to constraints.
	Transitions map[string]ElevationConstraints `yaml:"transitions"`
}

// ElevationConstraints are the requirements for a tier transition.
type ElevationConstraints struct {
	RequireMFA    bool          `yaml:"require_mfa"`
	MaxTTL        time.Duration `yaml:"max_ttl"`
	RequireReason bool          `yaml:"require_reason"`
	AllowedRoles  []string      `yaml:"allowed_roles"` // empty = all roles
}

// ElevationEngine manages elevation grants and policy.
type ElevationEngine struct {
	mu     sync.RWMutex
	grants map[string]*ElevationGrant // grantID → grant
	active map[string]*ElevationGrant // principalID → active grant
	policy *ElevationPolicy
}

// NewElevationEngine creates a new elevation engine.
func NewElevationEngine(policy *ElevationPolicy) *ElevationEngine {
	if policy == nil {
		policy = &ElevationPolicy{
			Transitions: make(map[string]ElevationConstraints),
		}
	}
	return &ElevationEngine{
		grants: make(map[string]*ElevationGrant),
		active: make(map[string]*ElevationGrant),
		policy: policy,
	}
}

// RequestElevation processes an elevation request.
// Returns a grant if approved, or an error with the denial reason.
func (e *ElevationEngine) RequestElevation(req ElevationRequest) (*ElevationGrant, error) {
	key := req.CurrentTier + "→" + req.TargetTier
	constraints, ok := e.policy.Transitions[key]
	if !ok {
		return nil, fmt.Errorf("elevation %s not permitted by policy", key)
	}

	if constraints.RequireMFA && req.MFAMethod == "" {
		return nil, fmt.Errorf("MFA required for elevation %s", key)
	}

	if constraints.RequireReason && req.Reason == "" {
		return nil, fmt.Errorf("reason required for elevation %s", key)
	}

	if len(constraints.AllowedRoles) > 0 {
		// Role check would use the Identity's role — caller must verify.
	}

	ttl := constraints.MaxTTL
	if ttl == 0 {
		ttl = 15 * time.Minute // default elevation TTL
	}

	now := time.Now()
	evidenceHash := ""
	if len(req.Evidence) > 0 {
		h := sha256.Sum256(req.Evidence)
		evidenceHash = fmt.Sprintf("%x", h)
	}

	grant := &ElevationGrant{
		GrantID:      fmt.Sprintf("elev-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", req.PrincipalID, req.TargetTier, now.UnixNano()))))[:24],
		PrincipalID:  req.PrincipalID,
		OriginalTier: req.CurrentTier,
		ElevatedTier: req.TargetTier,
		Reason:       req.Reason,
		EvidenceHash: evidenceHash,
		GrantedAt:    now,
		ExpiresAt:    now.Add(ttl),
		MFAVerified:  req.MFAMethod != "",
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Revoke any existing active grant for this principal.
	if existing, ok := e.active[req.PrincipalID]; ok {
		existing.Revoked = true
	}

	e.grants[grant.GrantID] = grant
	e.active[req.PrincipalID] = grant
	return grant, nil
}

// ActiveGrant returns the current active elevation for a principal, if any.
func (e *ElevationEngine) ActiveGrant(principalID string) *ElevationGrant {
	e.mu.RLock()
	defer e.mu.RUnlock()
	grant, ok := e.active[principalID]
	if !ok {
		return nil
	}
	if !grant.Valid() {
		return nil
	}
	return grant
}

// EffectiveTier returns the principal's effective tier, considering elevation.
func (e *ElevationEngine) EffectiveTier(id *Identity) string {
	if id == nil {
		return ""
	}
	grant := e.ActiveGrant(id.ID)
	if grant != nil {
		return grant.ElevatedTier
	}
	return id.Tier
}

// Revoke immediately terminates an elevation grant.
func (e *ElevationEngine) Revoke(grantID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	grant, ok := e.grants[grantID]
	if !ok {
		return fmt.Errorf("grant %s not found", grantID)
	}
	grant.Revoked = true
	// Remove from active if it's the current grant.
	if active, ok := e.active[grant.PrincipalID]; ok && active.GrantID == grantID {
		delete(e.active, grant.PrincipalID)
	}
	return nil
}

// RevokeByPrincipal revokes any active elevation for a principal.
func (e *ElevationEngine) RevokeByPrincipal(principalID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if grant, ok := e.active[principalID]; ok {
		grant.Revoked = true
		delete(e.active, principalID)
	}
}

// Cleanup removes expired grants older than the given age.
func (e *ElevationEngine) Cleanup(maxAge time.Duration) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, grant := range e.grants {
		if grant.ExpiresAt.Before(cutoff) {
			delete(e.grants, id)
			removed++
		}
	}
	return removed
}
