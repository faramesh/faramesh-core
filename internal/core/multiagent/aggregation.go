// Package multiagent — aggregation convergence governance.
//
// When multiple agents produce outputs that are synthesized into a final
// aggregated result, govern_output rules apply. Entity extraction detects
// sensitive data leaking across agent boundaries. Aggregate output policy
// controls what reaches the user.
package multiagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// AggregationSource represents one agent's contribution to an aggregate.
type AggregationSource struct {
	AgentID   string    `json:"agent_id"`
	DPRID     string    `json:"dpr_id"`
	Output    string    `json:"output"`
	Timestamp time.Time `json:"timestamp"`
}

// AggregateResult is the synthesized output from multiple agents.
type AggregateResult struct {
	SessionID  string   `json:"session_id"`
	Sources    []AggregationSource `json:"sources"`
	Synthesized string  `json:"synthesized"`
	Hash       string   `json:"hash"`
}

// EntityExtraction holds detected entities in aggregated output.
type EntityExtraction struct {
	EntityType string `json:"entity_type"` // "email", "pii", "credential", "url", "ip"
	Value      string `json:"value"`
	SourceAgent string `json:"source_agent"`
	Position   int    `json:"position"`
}

// AggregatePolicy defines governance for aggregated outputs.
type AggregatePolicy struct {
	MaxOutputLength    int      `json:"max_output_length"`
	BlockedEntityTypes []string `json:"blocked_entity_types"` // entity types to redact
	RequireAllSources  bool     `json:"require_all_sources"`  // all agents must contribute
	MinSources         int      `json:"min_sources"`
}

// AggregationGovernor governs synthesized multi-agent outputs.
type AggregationGovernor struct {
	mu       sync.Mutex
	policy   AggregatePolicy
	patterns map[string]*regexp.Regexp
}

// NewAggregationGovernor creates an aggregation governor.
func NewAggregationGovernor(policy AggregatePolicy) *AggregationGovernor {
	ag := &AggregationGovernor{
		policy: policy,
		patterns: map[string]*regexp.Regexp{
			"email":      regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			"ip":         regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			"credential": regexp.MustCompile(`(?i)(password|secret|api[_-]?key|token)\s*[=:]\s*\S+`),
			"ssn":        regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			"credit_card": regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
		},
	}
	return ag
}

// GoverOutput applies governance to an aggregated result.
// Returns the governed output, detected entities, and any denial reason.
func (ag *AggregationGovernor) GovernOutput(result AggregateResult) (string, []EntityExtraction, error) {
	ag.mu.Lock()
	defer ag.mu.Unlock()

	// Check minimum sources.
	if ag.policy.MinSources > 0 && len(result.Sources) < ag.policy.MinSources {
		return "", nil, fmt.Errorf("AGGREGATION_INCOMPLETE: need %d sources, got %d",
			ag.policy.MinSources, len(result.Sources))
	}

	// Extract entities from synthesized output.
	entities := ag.extractEntities(result)

	// Redact blocked entity types.
	output := result.Synthesized
	for _, entity := range entities {
		if ag.isBlocked(entity.EntityType) {
			output = redactEntity(output, entity.Value)
		}
	}

	// Check length limit.
	if ag.policy.MaxOutputLength > 0 && len(output) > ag.policy.MaxOutputLength {
		output = output[:ag.policy.MaxOutputLength] + "\n[OUTPUT TRUNCATED BY GOVERNANCE]"
	}

	return output, entities, nil
}

// HashAggregate computes a content hash for the aggregate for DPR.
func HashAggregate(result AggregateResult) string {
	h := sha256.New()
	h.Write([]byte(result.SessionID))
	for _, s := range result.Sources {
		h.Write([]byte(s.AgentID))
		h.Write([]byte(s.Output))
	}
	h.Write([]byte(result.Synthesized))
	return hex.EncodeToString(h.Sum(nil))
}

func (ag *AggregationGovernor) extractEntities(result AggregateResult) []EntityExtraction {
	var entities []EntityExtraction

	// Scan synthesized output.
	for entityType, pattern := range ag.patterns {
		matches := pattern.FindAllStringIndex(result.Synthesized, -1)
		for _, m := range matches {
			entities = append(entities, EntityExtraction{
				EntityType:  entityType,
				Value:       result.Synthesized[m[0]:m[1]],
				SourceAgent: ag.attributeToSource(result, m[0]),
				Position:    m[0],
			})
		}
	}

	return entities
}

func (ag *AggregationGovernor) attributeToSource(result AggregateResult, _ int) string {
	// Best-effort: attribute to first source. In production, would track
	// provenance through the synthesis pipeline.
	if len(result.Sources) > 0 {
		return result.Sources[0].AgentID
	}
	return "unknown"
}

func (ag *AggregationGovernor) isBlocked(entityType string) bool {
	for _, blocked := range ag.policy.BlockedEntityTypes {
		if blocked == entityType {
			return true
		}
	}
	return false
}

func redactEntity(text, entity string) string {
	redacted := "[REDACTED]"
	result := text
	for i := 0; i < len(result); {
		idx := indexOf(result[i:], entity)
		if idx < 0 {
			break
		}
		result = result[:i+idx] + redacted + result[i+idx+len(entity):]
		i += idx + len(redacted)
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
