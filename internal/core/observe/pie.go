// Package observe — Policy Intelligence Engine (PIE) analytics.
//
// Analyzes governance decision patterns over time to surface:
// - Dead rules (never match)
// - High-approval-rate DEFER rules (candidates for PERMIT)
// - Policy drift (rule behavior changing over time)
package observe

import (
	"sort"
	"sync"
	"time"
)

// RuleStats tracks decision statistics for a single policy rule.
type RuleStats struct {
	RuleID        string    `json:"rule_id"`
	Permits       int64     `json:"permits"`
	Denies        int64     `json:"denies"`
	Defers        int64     `json:"defers"`
	Approvals     int64     `json:"approvals"`  // DEFER → approved
	Rejections    int64     `json:"rejections"` // DEFER → rejected
	LastTriggered time.Time `json:"last_triggered"`
	FirstSeen     time.Time `json:"first_seen"`
}

// ApprovalRate returns the approval rate for DEFER decisions.
func (rs *RuleStats) ApprovalRate() float64 {
	total := rs.Approvals + rs.Rejections
	if total == 0 {
		return 0
	}
	return float64(rs.Approvals) / float64(total)
}

// TotalDecisions returns total decisions for this rule.
func (rs *RuleStats) TotalDecisions() int64 {
	return rs.Permits + rs.Denies + rs.Defers
}

// PIEAnalyzer provides Policy Intelligence Engine analytics.
type PIEAnalyzer struct {
	mu    sync.Mutex
	rules map[string]*RuleStats
}

// ObserveRule implements RuleObserver for pipeline decision hooks.
func (p *PIEAnalyzer) ObserveRule(obs RuleObservation) error {
	if obs.RuleID == "" {
		return nil
	}
	p.RecordRuleDecision(obs.RuleID, obs.Effect)
	return nil
}

// NewPIEAnalyzer creates a PIE analyzer.
func NewPIEAnalyzer() *PIEAnalyzer {
	return &PIEAnalyzer{
		rules: make(map[string]*RuleStats),
	}
}

// RecordRuleDecision records a decision for a specific rule.
func (p *PIEAnalyzer) RecordRuleDecision(ruleID, effect string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	stats, ok := p.rules[ruleID]
	if !ok {
		stats = &RuleStats{
			RuleID:    ruleID,
			FirstSeen: time.Now(),
		}
		p.rules[ruleID] = stats
	}

	stats.LastTriggered = time.Now()
	switch effect {
	case "PERMIT":
		stats.Permits++
	case "DENY":
		stats.Denies++
	case "DEFER":
		stats.Defers++
	}
}

// RecordDeferResolution records the outcome of a DEFER resolution.
func (p *PIEAnalyzer) RecordDeferResolution(ruleID string, approved bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	stats, ok := p.rules[ruleID]
	if !ok {
		return
	}
	if approved {
		stats.Approvals++
	} else {
		stats.Rejections++
	}
}

// DeadRules returns rules that haven't been triggered in the given duration.
func (p *PIEAnalyzer) DeadRules(inactiveDuration time.Duration) []RuleStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	cutoff := time.Now().Add(-inactiveDuration)
	var dead []RuleStats
	for _, stats := range p.rules {
		if stats.LastTriggered.Before(cutoff) {
			dead = append(dead, *stats)
		}
	}
	sort.Slice(dead, func(i, j int) bool {
		return dead[i].LastTriggered.Before(dead[j].LastTriggered)
	})
	return dead
}

// HighApprovalRules returns DEFER rules with approval rates above threshold,
// suggesting they could be promoted to PERMIT.
func (p *PIEAnalyzer) HighApprovalRules(threshold float64, minDefers int64) []PIERecommendation {
	p.mu.Lock()
	defer p.mu.Unlock()

	var recs []PIERecommendation
	for _, stats := range p.rules {
		if stats.Defers < minDefers {
			continue
		}
		rate := stats.ApprovalRate()
		if rate >= threshold {
			recs = append(recs, PIERecommendation{
				RuleID:       stats.RuleID,
				Type:         "promote_to_permit",
				ApprovalRate: rate,
				TotalDefers:  stats.Defers,
				Reason:       "High approval rate suggests this DEFER rule could be a PERMIT",
			})
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ApprovalRate > recs[j].ApprovalRate })
	return recs
}

// PolicyDrift detects rules whose behavior has changed significantly.
// A rule that used to PERMIT but now mostly DENYs (or vice versa) indicates drift.
func (p *PIEAnalyzer) PolicyDrift() []PIERecommendation {
	p.mu.Lock()
	defer p.mu.Unlock()

	var recs []PIERecommendation
	for _, stats := range p.rules {
		total := stats.TotalDecisions()
		if total < 100 {
			continue // need enough data
		}
		permitRate := float64(stats.Permits) / float64(total)
		denyRate := float64(stats.Denies) / float64(total)

		// Rule that almost always PERMITs might be redundant.
		if permitRate > 0.99 {
			recs = append(recs, PIERecommendation{
				RuleID: stats.RuleID,
				Type:   "nearly_always_permits",
				Reason: "Rule permits >99% of calls; consider if it's still needed",
			})
		}
		// Rule that almost always DENYs might be too broad.
		if denyRate > 0.95 {
			recs = append(recs, PIERecommendation{
				RuleID: stats.RuleID,
				Type:   "nearly_always_denies",
				Reason: "Rule denies >95% of calls; may be misconfigured or too broad",
			})
		}
	}
	return recs
}

// AllStats returns stats for all rules.
func (p *PIEAnalyzer) AllStats() []RuleStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := make([]RuleStats, 0, len(p.rules))
	for _, s := range p.rules {
		stats = append(stats, *s)
	}
	return stats
}

// PIERecommendation represents a policy intelligence recommendation.
type PIERecommendation struct {
	RuleID       string  `json:"rule_id"`
	Type         string  `json:"type"` // "promote_to_permit", "dead_rule", "nearly_always_permits", etc.
	ApprovalRate float64 `json:"approval_rate,omitempty"`
	TotalDefers  int64   `json:"total_defers,omitempty"`
	Reason       string  `json:"reason"`
}
