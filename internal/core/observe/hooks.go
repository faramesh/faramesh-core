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
