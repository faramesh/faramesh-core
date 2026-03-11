// Package principal — principal revocation API.
//
// Handles mid-session revocation of principal privileges. Revocation can be
// triggered by:
//   - IDP webhook (user disabled/deleted in Okta/Azure AD)
//   - Admin API call
//   - Policy violation threshold exceeded
//   - Session anomaly detection
//
// On revocation, the principal's tier reverts to the lowest allowed tier,
// any active elevation is cancelled, and all in-flight DEFER tokens for
// that principal are denied.
package principal

import (
	"sync"
	"time"
)

// RevocationEvent records a principal revocation.
type RevocationEvent struct {
	PrincipalID  string    `json:"principal_id"`
	RevokedAt    time.Time `json:"revoked_at"`
	Reason       string    `json:"reason"`   // idp_webhook, admin, policy_violation, anomaly
	Source       string    `json:"source"`    // okta, azure_ad, admin_api, policy_engine
	RevertToTier string    `json:"revert_to"` // tier to revert to (e.g., "free")
	Permanent    bool      `json:"permanent"` // if true, cannot be reinstated without admin action
}

// RevocationCallback is called when a principal is revoked.
// Implementations should cancel in-flight DEFER tokens, close sessions, etc.
type RevocationCallback func(event RevocationEvent)

// RevocationManager tracks revoked principals and triggers callbacks.
type RevocationManager struct {
	mu        sync.RWMutex
	revoked   map[string]*RevocationEvent // principalID → event
	callbacks []RevocationCallback
	elevation *ElevationEngine // optional: to cancel elevations on revocation
}

// NewRevocationManager creates a new revocation manager.
func NewRevocationManager(elevation *ElevationEngine) *RevocationManager {
	return &RevocationManager{
		revoked:   make(map[string]*RevocationEvent),
		elevation: elevation,
	}
}

// OnRevocation registers a callback to be invoked on revocation.
func (rm *RevocationManager) OnRevocation(cb RevocationCallback) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.callbacks = append(rm.callbacks, cb)
}

// Revoke revokes a principal's privileges.
func (rm *RevocationManager) Revoke(event RevocationEvent) {
	event.RevokedAt = time.Now()

	rm.mu.Lock()
	rm.revoked[event.PrincipalID] = &event
	cbs := make([]RevocationCallback, len(rm.callbacks))
	copy(cbs, rm.callbacks)
	rm.mu.Unlock()

	// Cancel any active elevation.
	if rm.elevation != nil {
		rm.elevation.RevokeByPrincipal(event.PrincipalID)
	}

	// Fire callbacks outside the lock.
	for _, cb := range cbs {
		cb(event)
	}
}

// IsRevoked checks if a principal is currently revoked.
func (rm *RevocationManager) IsRevoked(principalID string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	_, ok := rm.revoked[principalID]
	return ok
}

// GetRevocation returns the revocation event for a principal, if any.
func (rm *RevocationManager) GetRevocation(principalID string) *RevocationEvent {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.revoked[principalID]
}

// RevertedTier returns the tier a revoked principal should be treated as.
// Returns the original tier if the principal is not revoked.
func (rm *RevocationManager) RevertedTier(id *Identity) string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if event, ok := rm.revoked[id.ID]; ok {
		if event.RevertToTier != "" {
			return event.RevertToTier
		}
		return "free" // default to lowest tier
	}
	return id.Tier
}

// Reinstate removes a non-permanent revocation.
func (rm *RevocationManager) Reinstate(principalID string) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	event, ok := rm.revoked[principalID]
	if !ok {
		return false
	}
	if event.Permanent {
		return false // permanent revocations require admin escalation
	}
	delete(rm.revoked, principalID)
	return true
}

// RevokedPrincipals returns all currently revoked principal IDs.
func (rm *RevocationManager) RevokedPrincipals() []string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	ids := make([]string, 0, len(rm.revoked))
	for id := range rm.revoked {
		ids = append(ids, id)
	}
	return ids
}
