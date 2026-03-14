package dpr

import "fmt"

// MultiStore mirrors writes to a secondary backend while keeping a primary
// backend for reads and chain-seeding queries.
type MultiStore struct {
	primary   StoreBackend
	secondary StoreBackend
}

// NewMultiStore constructs a dual-write store.
func NewMultiStore(primary, secondary StoreBackend) *MultiStore {
	return &MultiStore{primary: primary, secondary: secondary}
}

func (m *MultiStore) Save(rec *Record) error {
	if m.primary != nil {
		if err := m.primary.Save(rec); err != nil {
			return err
		}
	}
	if m.secondary != nil {
		if err := m.secondary.Save(rec); err != nil {
			return fmt.Errorf("secondary save: %w", err)
		}
	}
	return nil
}

func (m *MultiStore) ByID(recordID string) (*Record, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("primary store is not configured")
	}
	return m.primary.ByID(recordID)
}

func (m *MultiStore) RecentByAgent(agentID string, limit int) ([]*Record, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("primary store is not configured")
	}
	return m.primary.RecentByAgent(agentID, limit)
}

func (m *MultiStore) Recent(limit int) ([]*Record, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("primary store is not configured")
	}
	return m.primary.Recent(limit)
}

func (m *MultiStore) LastHash(agentID string) (string, error) {
	if m.primary == nil {
		return "", fmt.Errorf("primary store is not configured")
	}
	return m.primary.LastHash(agentID)
}

func (m *MultiStore) KnownAgents() ([]string, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("primary store is not configured")
	}
	return m.primary.KnownAgents()
}

func (m *MultiStore) VerifyChain(agentID string) (*ChainBreak, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("primary store is not configured")
	}
	return m.primary.VerifyChain(agentID)
}

func (m *MultiStore) Close() error {
	if m.primary != nil {
		if err := m.primary.Close(); err != nil {
			return err
		}
	}
	if m.secondary != nil {
		if err := m.secondary.Close(); err != nil {
			return err
		}
	}
	return nil
}
