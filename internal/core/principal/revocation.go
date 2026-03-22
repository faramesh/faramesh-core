package principal

import (
	"strings"
	"sync"
	"time"
)

type RevocationEvent struct {
	PrincipalID  string
	Reason       string
	Source       string
	RevertToTier string
	CreatedAt    time.Time
}

type RevocationManager struct {
	mu         sync.RWMutex
	revoked    map[string]RevocationEvent
	elevations *ElevationEngine
}

func NewRevocationManager(elevations *ElevationEngine) *RevocationManager {
	return &RevocationManager{
		revoked:    make(map[string]RevocationEvent),
		elevations: elevations,
	}
}

func (m *RevocationManager) Revoke(ev RevocationEvent) {
	id := strings.TrimSpace(ev.PrincipalID)
	if id == "" {
		return
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now()
	}
	m.mu.Lock()
	m.revoked[id] = ev
	m.mu.Unlock()
}

func (m *RevocationManager) IsRevoked(principalID string) bool {
	if m == nil || strings.TrimSpace(principalID) == "" {
		return false
	}
	m.mu.RLock()
	_, ok := m.revoked[principalID]
	m.mu.RUnlock()
	return ok
}
