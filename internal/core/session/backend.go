// Package session provides the Backend interface for session state storage.
// The default in-memory implementation is used for single-node deployments.
// The Redis implementation provides shared state for multi-node clusters.
package session

import "context"

// Backend defines the storage interface for session state operations.
// All methods must be safe for concurrent use. Implementations must be
// fail-fast: if the backend is unavailable, return an error immediately
// so the degraded mode manager can transition to stateless mode.
type Backend interface {
	// IncrCallCount atomically increments the call counter for an agent
	// and returns the new value. The counter is scoped to a session.
	IncrCallCount(ctx context.Context, agentID, sessionID string) (int64, error)

	// GetCallCount returns the current call count without incrementing.
	GetCallCount(ctx context.Context, agentID, sessionID string) (int64, error)

	// AddCost atomically adds costUSD to both session and daily counters.
	// Returns (newSessionCost, newDailyCost, err).
	AddCost(ctx context.Context, agentID, sessionID string, costUSD float64) (float64, float64, error)

	// GetSessionCost returns the total session cost in USD.
	GetSessionCost(ctx context.Context, agentID, sessionID string) (float64, error)

	// GetDailyCost returns the total daily cost in USD (UTC calendar day).
	GetDailyCost(ctx context.Context, agentID string) (float64, error)

	// RecordHistory appends a history entry. maxEntries limits the ring buffer.
	RecordHistory(ctx context.Context, agentID, sessionID string, entry HistoryEntry, maxEntries int) error

	// GetHistory returns the most recent history entries, newest first.
	GetHistory(ctx context.Context, agentID, sessionID string, limit int) ([]HistoryEntry, error)

	// SetKillSwitch atomically sets the kill switch for an agent.
	SetKillSwitch(ctx context.Context, agentID string) error

	// IsKilled checks whether the kill switch is active for an agent.
	IsKilled(ctx context.Context, agentID string) (bool, error)

	// CheckAndReserveCost atomically checks if adding costUSD would exceed
	// sessionLimit or dailyLimit, and if not, reserves the cost.
	// Returns (permitted bool, err error). This enables two-phase cost
	// reservation per the plan's "Reserve → Execute → Confirm/Rollback" pattern.
	CheckAndReserveCost(ctx context.Context, agentID, sessionID string,
		costUSD, sessionLimit, dailyLimit float64) (bool, error)

	// ConfirmCost confirms a previously reserved cost (no-op for simple backends).
	ConfirmCost(ctx context.Context, agentID, sessionID string, costUSD float64) error

	// RollbackCost rolls back a previously reserved cost.
	RollbackCost(ctx context.Context, agentID, sessionID string, costUSD float64) error

	// Close releases backend resources.
	Close() error
}
