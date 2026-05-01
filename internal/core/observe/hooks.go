package observe

import "time"

// AccessEvent is emitted for PERMIT decisions for cross-session analysis.
type AccessEvent struct {
	AgentID     string
	SessionID   string
	ToolID      string
	RuleID      string
	Timestamp   time.Time
	PrincipalID string
	DPRID       string
}

// RuleObservation is emitted for decisions with a matched rule ID.
type RuleObservation struct {
	AgentID   string
	SessionID string
	ToolID    string
	RuleID    string
	Effect    string
	Timestamp time.Time
}

// SemanticDriftObservation captures a scored semantic drift event.
type SemanticDriftObservation struct {
	ProviderID    string
	SessionID     string
	AggregateHash string
	Similarity    float64
	Distance      float64
	Threshold     float64
	SourceCount   int
	Triggered     bool
	Denied        bool
	Timestamp     time.Time
}

// CrossSessionTracker records PERMIT access events.
type CrossSessionTracker interface {
	RecordAccess(AccessEvent) error
}

type noOpCrossSessionTracker struct{}

func (noOpCrossSessionTracker) RecordAccess(AccessEvent) error { return nil }

// RuleObserver receives per-rule decision observations.
type RuleObserver interface {
	ObserveRule(RuleObservation) error
}

type noOpRuleObserver struct{}

func (noOpRuleObserver) ObserveRule(RuleObservation) error { return nil }

// SemanticDriftObserver receives scored semantic drift events.
type SemanticDriftObserver interface {
	ObserveSemanticDrift(SemanticDriftObservation) error
}

type noOpSemanticDriftObserver struct{}

func (noOpSemanticDriftObserver) ObserveSemanticDrift(SemanticDriftObservation) error { return nil }
