package session

import "context"

// MemoryBackend implements Backend using in-memory State objects.
// This is the default for single-node deployments and testing.
type MemoryBackend struct {
	mgr *Manager
}

// NewMemoryBackend wraps a Manager as a Backend.
func NewMemoryBackend(mgr *Manager) *MemoryBackend {
	return &MemoryBackend{mgr: mgr}
}

func (b *MemoryBackend) IncrCallCount(_ context.Context, agentID, _ string) (int64, error) {
	return b.mgr.Get(agentID).IncrCallCount(), nil
}

func (b *MemoryBackend) GetCallCount(_ context.Context, agentID, _ string) (int64, error) {
	return b.mgr.Get(agentID).CallCount(), nil
}

func (b *MemoryBackend) AddCost(_ context.Context, agentID, _ string, costUSD float64) (float64, float64, error) {
	s := b.mgr.Get(agentID)
	s.AddCost(costUSD)
	return s.CurrentCostUSD(), s.DailyCostUSD(), nil
}

func (b *MemoryBackend) GetSessionCost(_ context.Context, agentID, _ string) (float64, error) {
	return b.mgr.Get(agentID).CurrentCostUSD(), nil
}

func (b *MemoryBackend) GetDailyCost(_ context.Context, agentID string) (float64, error) {
	return b.mgr.Get(agentID).DailyCostUSD(), nil
}

func (b *MemoryBackend) RecordHistory(_ context.Context, agentID, _ string, entry HistoryEntry, _ int) error {
	b.mgr.Get(agentID).RecordHistory(entry.ToolID, entry.Effect)
	return nil
}

func (b *MemoryBackend) GetHistory(_ context.Context, agentID, _ string, _ int) ([]HistoryEntry, error) {
	return b.mgr.Get(agentID).History(), nil
}

func (b *MemoryBackend) SetKillSwitch(_ context.Context, agentID string) error {
	b.mgr.Kill(agentID)
	return nil
}

func (b *MemoryBackend) IsKilled(_ context.Context, agentID string) (bool, error) {
	return b.mgr.Get(agentID).IsKilled(), nil
}

func (b *MemoryBackend) CheckAndReserveCost(_ context.Context, agentID, _ string,
	costUSD, sessionLimit, dailyLimit float64) (bool, error) {
	s := b.mgr.Get(agentID)
	if sessionLimit > 0 && s.CurrentCostUSD()+costUSD > sessionLimit {
		return false, nil
	}
	if dailyLimit > 0 && s.DailyCostUSD()+costUSD > dailyLimit {
		return false, nil
	}
	s.AddCost(costUSD)
	return true, nil
}

func (b *MemoryBackend) ConfirmCost(_ context.Context, _, _ string, _ float64) error {
	return nil // no-op for in-memory
}

func (b *MemoryBackend) RollbackCost(_ context.Context, agentID, _ string, costUSD float64) error {
	s := b.mgr.Get(agentID)
	s.AddCost(-costUSD)
	return nil
}

func (b *MemoryBackend) Close() error { return nil }
