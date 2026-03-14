package dpr

// StoreBackend defines the interface for DPR record persistence.
// The SQLite implementation is used for single-node deployments.
// The PostgreSQL implementation is used for production multi-node clusters.
type StoreBackend interface {
	// Save persists a DPR record. Called asynchronously after WAL write.
	Save(rec *Record) error

	// ByID returns one record by its record_id.
	ByID(recordID string) (*Record, error)

	// RecentByAgent returns records for a specific agent, newest first.
	RecentByAgent(agentID string, limit int) ([]*Record, error)

	// Recent returns records across all agents, newest first.
	Recent(limit int) ([]*Record, error)

	// LastHash returns the most recent record_hash for an agent.
	// Used to seed the chain hash on restart.
	LastHash(agentID string) (string, error)

	// KnownAgents returns all distinct agent IDs with records.
	KnownAgents() ([]string, error)

	// VerifyChain checks chain integrity for an agent's records.
	// Returns the first broken link or nil if the chain is valid.
	VerifyChain(agentID string) (*ChainBreak, error)

	// Close releases backend resources.
	Close() error
}

// ChainBreak describes a break in the DPR hash chain.
type ChainBreak struct {
	RecordID       string
	ExpectedHash   string
	ActualHash     string
	PrevRecordHash string
	Position       int
}
