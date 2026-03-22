package principal

import (
	"errors"
	"strings"
	"sync"
	"time"
)

type ElevationConstraints struct {
	RequireMFA bool
	MaxTTL     time.Duration
}

type ElevationPolicy struct {
	Transitions map[string]ElevationConstraints
}

type ElevationRequest struct {
	PrincipalID string
	CurrentTier string
	TargetTier  string
	MFAMethod   string
	Reason      string
	TTL         time.Duration
}

type ElevationGrant struct {
	PrincipalID  string
	FromTier     string
	ElevatedTier string
	Reason       string
	GrantedAt    time.Time
	ExpiresAt    time.Time
}

type ElevationEngine struct {
	mu      sync.RWMutex
	policy  *ElevationPolicy
	grants  map[string]*ElevationGrant
	nowFunc func() time.Time
}

func NewElevationEngine(policy *ElevationPolicy) *ElevationEngine {
	return &ElevationEngine{
		policy:  policy,
		grants:  make(map[string]*ElevationGrant),
		nowFunc: time.Now,
	}
}

func (e *ElevationEngine) RequestElevation(req ElevationRequest) (*ElevationGrant, error) {
	if strings.TrimSpace(req.PrincipalID) == "" {
		return nil, errors.New("principal id is required")
	}
	if strings.TrimSpace(req.TargetTier) == "" {
		return nil, errors.New("target tier is required")
	}
	constraints := ElevationConstraints{}
	if e.policy != nil {
		key := strings.TrimSpace(req.CurrentTier) + "→" + strings.TrimSpace(req.TargetTier)
		if c, ok := e.policy.Transitions[key]; ok {
			constraints = c
		}
	}
	if constraints.RequireMFA && strings.TrimSpace(req.MFAMethod) == "" {
		return nil, errors.New("mfa required for elevation")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if constraints.MaxTTL > 0 && ttl > constraints.MaxTTL {
		ttl = constraints.MaxTTL
	}
	now := e.nowFunc()
	grant := &ElevationGrant{
		PrincipalID:  req.PrincipalID,
		FromTier:     req.CurrentTier,
		ElevatedTier: req.TargetTier,
		Reason:       req.Reason,
		GrantedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}
	e.mu.Lock()
	e.grants[req.PrincipalID] = grant
	e.mu.Unlock()
	return grant, nil
}

func (e *ElevationEngine) ActiveGrant(principalID string) *ElevationGrant {
	if e == nil || strings.TrimSpace(principalID) == "" {
		return nil
	}
	now := e.nowFunc()
	e.mu.RLock()
	grant := e.grants[principalID]
	e.mu.RUnlock()
	if grant == nil {
		return nil
	}
	if !grant.ExpiresAt.IsZero() && now.After(grant.ExpiresAt) {
		e.mu.Lock()
		delete(e.grants, principalID)
		e.mu.Unlock()
		return nil
	}
	return grant
}
