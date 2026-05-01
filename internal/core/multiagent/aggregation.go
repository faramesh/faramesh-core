// Package multiagent — aggregation convergence governance.
//
// When multiple agents produce outputs that are synthesized into a final
// aggregated result, govern_output rules apply. Entity extraction detects
// sensitive data leaking across agent boundaries. Aggregate output policy
// controls what reaches the user.
package multiagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/semantic"
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
	SessionID   string              `json:"session_id"`
	Sources     []AggregationSource `json:"sources"`
	Synthesized string              `json:"synthesized"`
	Hash        string              `json:"hash"`
}

// EntityExtraction holds detected entities in aggregated output.
type EntityExtraction struct {
	EntityType  string `json:"entity_type"` // "email", "pii", "credential", "url", "ip"
	Value       string `json:"value"`
	SourceAgent string `json:"source_agent"`
	Position    int    `json:"position"`
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
	runtime  AggregationRuntimeConfig
	sessions map[string][]aggregationRuntimeEvent
	semantic SemanticDriftConfig
	provider semantic.Provider
	semanticObserver observe.SemanticDriftObserver
	drifts   []SemanticDriftEvent
}

type AggregationRuntimeConfig struct {
	Enabled         bool
	Window          time.Duration
	MaxRiskyActions int
}

type aggregationRuntimeEvent struct {
	ts     time.Time
	weight int
}

// SemanticDriftConfig controls semantic drift scoring for aggregate outputs.
type SemanticDriftConfig struct {
	Enabled          bool
	Threshold        float64
	MinSourceCount   int
	DenyOnThreshold  bool
	CacheTTL         time.Duration
	CacheEntries     int
	MaxEvents        int
}

// SemanticDriftEvent captures one scoring decision.
type SemanticDriftEvent struct {
	SessionID     string    `json:"session_id"`
	AggregateHash string    `json:"aggregate_hash"`
	ProviderID    string    `json:"provider_id"`
	Similarity    float64   `json:"similarity"`
	Distance      float64   `json:"distance"`
	Threshold     float64   `json:"threshold"`
	SourceCount   int       `json:"source_count"`
	Triggered     bool      `json:"triggered"`
	ObservedAt    time.Time `json:"observed_at"`
}

// NewAggregationGovernor creates an aggregation governor.
func NewAggregationGovernor(policy AggregatePolicy) *AggregationGovernor {
	ag := &AggregationGovernor{
		policy: policy,
		patterns: map[string]*regexp.Regexp{
			"email":       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			"ip":          regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			"credential":  regexp.MustCompile(`(?i)(password|secret|api[_-]?key|token)\s*[=:]\s*\S+`),
			"ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			"credit_card": regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
		},
		sessions: make(map[string][]aggregationRuntimeEvent),
	}
	return ag
}

func (ag *AggregationGovernor) ConfigureRuntime(cfg AggregationRuntimeConfig) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	ag.runtime = cfg
}

// ConfigureSemanticDrift enables semantic drift scoring for synthesized output.
func (ag *AggregationGovernor) ConfigureSemanticDrift(provider semantic.Provider, cfg SemanticDriftConfig) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if provider != nil && (cfg.CacheTTL > 0 || cfg.CacheEntries > 0) {
		provider = semantic.NewCachingProvider(provider, cfg.CacheTTL, cfg.CacheEntries)
	}
	ag.provider = provider
	ag.semantic = cfg
	if ag.semanticObserver == nil {
		ag.semanticObserver = observe.Default
	}
}

// SetSemanticDriftObserver wires semantic drift events into telemetry or other sinks.
func (ag *AggregationGovernor) SetSemanticDriftObserver(observer observe.SemanticDriftObserver) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	ag.semanticObserver = observer
}

// SemanticDriftObserver returns the currently configured drift observer.
func (ag *AggregationGovernor) SemanticDriftObserver() observe.SemanticDriftObserver {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.semanticObserver
}

// SemanticDriftEvents returns the observed semantic drift scores.
func (ag *AggregationGovernor) SemanticDriftEvents() []SemanticDriftEvent {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	out := make([]SemanticDriftEvent, len(ag.drifts))
	copy(out, ag.drifts)
	return out
}

func (ag *AggregationGovernor) CheckAndTrack(sessionID string, riskyWeight int, now time.Time) (bool, string, string) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	cfg := ag.runtime
	if !cfg.Enabled || cfg.Window <= 0 || cfg.MaxRiskyActions <= 0 {
		return true, "", ""
	}
	if riskyWeight <= 0 {
		return true, "", ""
	}
	events := ag.sessions[sessionID]
	cutoff := now.Add(-cfg.Window)
	kept := events[:0]
	total := 0
	for _, evt := range events {
		if evt.ts.After(cutoff) || evt.ts.Equal(cutoff) {
			kept = append(kept, evt)
			total += evt.weight
		}
	}
	if total+riskyWeight > cfg.MaxRiskyActions {
		ag.sessions[sessionID] = append(kept, aggregationRuntimeEvent{ts: now, weight: riskyWeight})
		return false, "AGGREGATE_BUDGET_EXCEEDED", fmt.Sprintf("aggregation governor blocked risky action budget (%d/%d in %s)", total+riskyWeight, cfg.MaxRiskyActions, cfg.Window)
	}
	ag.sessions[sessionID] = append(kept, aggregationRuntimeEvent{ts: now, weight: riskyWeight})
	return true, "", ""
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

	if err := ag.scoreSemanticDriftLocked(result, output); err != nil {
		return "", entities, err
	}

	return output, entities, nil
}

func (ag *AggregationGovernor) scoreSemanticDriftLocked(result AggregateResult, governedOutput string) error {
	cfg := ag.semantic
	if !cfg.Enabled || ag.provider == nil {
		return nil
	}
	if cfg.MinSourceCount > 0 && len(result.Sources) < cfg.MinSourceCount {
		return nil
	}
	if strings.TrimSpace(governedOutput) == "" {
		return nil
	}

	texts := make([]string, 0, len(result.Sources)+1)
	for _, source := range result.Sources {
		if trimmed := strings.TrimSpace(source.Output); trimmed != "" {
			texts = append(texts, trimmed)
		}
	}
	if len(texts) == 0 {
		return nil
	}
	texts = append(texts, strings.TrimSpace(governedOutput))

	vecs, err := ag.provider.Embed(context.Background(), texts)
	if err != nil {
		return fmt.Errorf("semantic drift embed: %w", err)
	}
	if len(vecs) != len(texts) {
		return fmt.Errorf("semantic drift embed: provider %q returned %d vectors for %d texts", ag.provider.ID(), len(vecs), len(texts))
	}

	centroid, err := semantic.Centroid(vecs[:len(vecs)-1])
	if err != nil {
		return fmt.Errorf("semantic drift centroid: %w", err)
	}
	similarity, err := semantic.CosineSimilarity(centroid, vecs[len(vecs)-1])
	if err != nil {
		return fmt.Errorf("semantic drift similarity: %w", err)
	}
	distance := 1 - similarity
	triggered := cfg.Threshold > 0 && distance > cfg.Threshold
	ag.drifts = append(ag.drifts, SemanticDriftEvent{
		SessionID:     result.SessionID,
		AggregateHash: result.Hash,
		ProviderID:    ag.provider.ID(),
		Similarity:    similarity,
		Distance:      distance,
		Threshold:     cfg.Threshold,
		SourceCount:   len(result.Sources),
		Triggered:     triggered,
		ObservedAt:    time.Now().UTC(),
	})
	if cfg.MaxEvents > 0 && len(ag.drifts) > cfg.MaxEvents {
		ag.drifts = append([]SemanticDriftEvent(nil), ag.drifts[len(ag.drifts)-cfg.MaxEvents:]...)
	}
	if observer := ag.semanticObserver; observer != nil {
		_ = observer.ObserveSemanticDrift(observe.SemanticDriftObservation{
			ProviderID:    ag.provider.ID(),
			SessionID:     result.SessionID,
			AggregateHash: result.Hash,
			Similarity:    similarity,
			Distance:      distance,
			Threshold:     cfg.Threshold,
			SourceCount:   len(result.Sources),
			Triggered:     triggered,
			Denied:        triggered && cfg.DenyOnThreshold,
			Timestamp:     time.Now().UTC(),
		})
	}
	if triggered && cfg.DenyOnThreshold {
		return fmt.Errorf("SEMANTIC_DRIFT_EXCEEDED: distance %.4f exceeds threshold %.4f", distance, cfg.Threshold)
	}
	return nil
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
