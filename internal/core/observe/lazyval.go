// Package observe — lazy validation mode.
//
// After a session ends, performs async chain-level analysis across all
// DPR records in the session. Applies chain-level policies that can't be
// evaluated in real-time (requires full session context). Flags violations
// and creates incidents.
package observe

import (
	"fmt"
	"sync"
	"time"
)

// ChainPolicy defines a policy evaluated across the full session chain.
type ChainPolicy struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	// CheckFunc evaluates the full session chain and returns violations.
	CheckFunc func(chain []ChainRecord) []ChainViolation
}

// ChainRecord is a simplified DPR record for chain analysis.
type ChainRecord struct {
	RecordID    string            `json:"record_id"`
	ToolID      string            `json:"tool_id"`
	Effect      string            `json:"effect"`
	ReasonCode  string            `json:"reason_code"`
	Timestamp   time.Time         `json:"timestamp"`
	Args        map[string]any    `json:"args,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ChainViolation represents a policy violation found during lazy validation.
type ChainViolation struct {
	PolicyID    string   `json:"policy_id"`
	Severity    string   `json:"severity"` // "critical", "high", "medium", "low"
	Description string   `json:"description"`
	RecordIDs   []string `json:"record_ids"` // involved DPR records
}

// Incident represents a security/compliance incident from chain analysis.
type Incident struct {
	ID          string           `json:"id"`
	SessionID   string           `json:"session_id"`
	PrincipalID string           `json:"principal_id"`
	Violations  []ChainViolation `json:"violations"`
	CreatedAt   time.Time        `json:"created_at"`
	Severity    string           `json:"severity"`
}

// LazyValidator performs post-session chain analysis.
type LazyValidator struct {
	mu       sync.Mutex
	policies []ChainPolicy
	incidents []Incident
	incidentCounter int
}

// NewLazyValidator creates a lazy validator.
func NewLazyValidator() *LazyValidator {
	return &LazyValidator{}
}

// AddPolicy registers a chain policy for lazy validation.
func (lv *LazyValidator) AddPolicy(policy ChainPolicy) {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	lv.policies = append(lv.policies, policy)
}

// ValidateChain runs all chain policies against a completed session.
// Returns violations and any created incident.
func (lv *LazyValidator) ValidateChain(sessionID, principalID string, chain []ChainRecord) (*Incident, []ChainViolation) {
	lv.mu.Lock()
	defer lv.mu.Unlock()

	var allViolations []ChainViolation
	for _, policy := range lv.policies {
		violations := policy.CheckFunc(chain)
		allViolations = append(allViolations, violations...)
	}

	if len(allViolations) == 0 {
		return nil, nil
	}

	// Create incident with highest severity from violations.
	severity := "low"
	for _, v := range allViolations {
		if severityRank(v.Severity) > severityRank(severity) {
			severity = v.Severity
		}
	}

	lv.incidentCounter++
	incident := Incident{
		ID:          fmt.Sprintf("INC-%06d", lv.incidentCounter),
		SessionID:   sessionID,
		PrincipalID: principalID,
		Violations:  allViolations,
		CreatedAt:   time.Now(),
		Severity:    severity,
	}
	lv.incidents = append(lv.incidents, incident)

	return &incident, allViolations
}

// Incidents returns all recorded incidents.
func (lv *LazyValidator) Incidents() []Incident {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	out := make([]Incident, len(lv.incidents))
	copy(out, lv.incidents)
	return out
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// ── Built-In Chain Policies ──

// ExcessivePermitChainPolicy flags sessions with unusually high permit rates.
func ExcessivePermitChainPolicy(threshold float64) ChainPolicy {
	return ChainPolicy{
		ID:          "excessive_permits",
		Description: "Flags sessions where permit rate exceeds threshold",
		CheckFunc: func(chain []ChainRecord) []ChainViolation {
			if len(chain) < 10 {
				return nil
			}
			permits := 0
			for _, r := range chain {
				if r.Effect == "PERMIT" {
					permits++
				}
			}
			rate := float64(permits) / float64(len(chain))
			if rate > threshold {
				return []ChainViolation{{
					PolicyID:    "excessive_permits",
					Severity:    "medium",
					Description: fmt.Sprintf("Session permit rate %.1f%% exceeds threshold %.1f%%", rate*100, threshold*100),
				}}
			}
			return nil
		},
	}
}

// RapidFireToolPolicy flags sessions with unusually rapid tool invocations.
func RapidFireToolPolicy(maxCallsPerMinute int) ChainPolicy {
	return ChainPolicy{
		ID:          "rapid_fire_tools",
		Description: "Flags sessions with too many tool calls per minute",
		CheckFunc: func(chain []ChainRecord) []ChainViolation {
			if len(chain) < 2 {
				return nil
			}
			duration := chain[len(chain)-1].Timestamp.Sub(chain[0].Timestamp)
			if duration <= 0 {
				return nil
			}
			callsPerMinute := float64(len(chain)) / duration.Minutes()
			if callsPerMinute > float64(maxCallsPerMinute) {
				return []ChainViolation{{
					PolicyID:    "rapid_fire_tools",
					Severity:    "high",
					Description: fmt.Sprintf("Session averaged %.0f calls/min (max %d)", callsPerMinute, maxCallsPerMinute),
				}}
			}
			return nil
		},
	}
}
