package governstate

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

// Tracker holds durable budget and rate-limit counters replayed from WAL control frames.
type Tracker struct {
	mu sync.Mutex

	budgetSpent   map[string]float64 // agent|scope -> spent USD
	budgetCeiling map[string]float64 // agent|scope -> ceiling USD
	rateCounts    map[string]int64   // agent|tool|window -> count
	rateLimits    map[string]int64   // agent|tool|window -> limit
	rateWindows   map[string]time.Time
}

func New() *Tracker {
	return &Tracker{
		budgetSpent:   make(map[string]float64),
		budgetCeiling: make(map[string]float64),
		rateCounts:    make(map[string]int64),
		rateLimits:    make(map[string]int64),
		rateWindows:   make(map[string]time.Time),
	}
}

func budgetKey(agentID, scope string) string {
	return agentID + "|" + scope
}

func rateKey(agentID, tool, window string) string {
	return agentID + "|" + tool + "|" + window
}

// ReplayFromWAL loads BUDGET_UPDATE and RATE_UPDATE frames from wal.
func (t *Tracker) ReplayFromWAL(wal *dpr.WAL) error {
	if wal == nil {
		return nil
	}
	return wal.ReplayControl(func(frame *dpr.ControlFrame) error {
		t.Apply(frame)
		return nil
	})
}

// Apply updates in-memory state from a control frame.
func (t *Tracker) Apply(frame *dpr.ControlFrame) {
	if frame == nil || frame.AgentID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch frame.FrameKind {
	case dpr.FrameKindBudgetUpdate:
		k := budgetKey(frame.AgentID, frame.Scope)
		t.budgetSpent[k] = frame.SpentUSD
		if frame.CeilingUSD > 0 {
			t.budgetCeiling[k] = frame.CeilingUSD
		}
	case dpr.FrameKindRateUpdate:
		k := rateKey(frame.AgentID, frame.Tool, frame.Window)
		t.rateCounts[k] = frame.Count
		if frame.Limit > 0 {
			t.rateLimits[k] = frame.Limit
		}
	}
}

// SetBudget persists budget counters (also used after replay).
func (t *Tracker) SetBudget(agentID, scope string, spent, ceiling float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := budgetKey(agentID, scope)
	t.budgetSpent[k] = spent
	if ceiling > 0 {
		t.budgetCeiling[k] = ceiling
	}
}

func (t *Tracker) BudgetSpent(agentID, scope string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.budgetSpent[budgetKey(agentID, scope)]
}

// CheckRate returns exceeded, limit, window duration if the call should be denied.
func (t *Tracker) CheckRate(agentID, toolID string, rules []agentgov.RateLimit, now time.Time) (exceeded bool, matched agentgov.RateLimit) {
	if len(rules) == 0 {
		return false, agentgov.RateLimit{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, rule := range rules {
		if !toolMatches(rule.Tool, toolID) {
			continue
		}
		win := parseWindow(rule.Window)
		k := rateKey(agentID, rule.Tool, rule.Window)
		limit := rule.Limit
		if lim, ok := t.rateLimits[k]; ok && lim > 0 {
			limit = lim
		}
		if limit <= 0 {
			continue
		}
		start := t.rateWindows[k]
		if start.IsZero() || now.Sub(start) >= win {
			t.rateWindows[k] = now
			t.rateCounts[k] = 0
		}
		if t.rateCounts[k] >= limit {
			return true, rule
		}
		matched = rule
	}
	return false, matched
}

// RecordRate increments the counter for a matched rule after a permitted call.
func (t *Tracker) RecordRate(agentID string, rule agentgov.RateLimit, now time.Time) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := rateKey(agentID, rule.Tool, rule.Window)
	win := parseWindow(rule.Window)
	start := t.rateWindows[k]
	if start.IsZero() || now.Sub(start) >= win {
		t.rateWindows[k] = now
		t.rateCounts[k] = 0
	}
	t.rateCounts[k]++
	if rule.Limit > 0 {
		t.rateLimits[k] = rule.Limit
	}
	return t.rateCounts[k]
}

// ToolMatches reports whether a rate-limit or redact tool pattern matches toolID.
func ToolMatches(pattern, toolID string) bool {
	return toolMatches(pattern, toolID)
}

func toolMatches(pattern, toolID string) bool {
	pattern = strings.TrimSpace(pattern)
	toolID = strings.TrimSpace(toolID)
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == toolID {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(toolID, prefix)
	}
	if strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, toolID)
		return ok
	}
	return false
}

func parseWindow(window string) time.Duration {
	w := strings.TrimSpace(strings.ToLower(window))
	switch w {
	case "second", "1s", "s":
		return time.Second
	case "minute", "1m", "min":
		return time.Minute
	case "hour", "1h", "hr":
		return time.Hour
	case "day", "1d":
		return 24 * time.Hour
	default:
		if d, err := time.ParseDuration(w); err == nil {
			return d
		}
		return time.Minute
	}
}

// BudgetControlFrame builds a WAL budget update frame.
func BudgetControlFrame(agentID, scope string, spent, ceiling float64) *dpr.ControlFrame {
	return &dpr.ControlFrame{
		FrameKind:  dpr.FrameKindBudgetUpdate,
		AgentID:    agentID,
		Scope:      scope,
		SpentUSD:   spent,
		CeilingUSD: ceiling,
	}
}

// RateControlFrame builds a WAL rate update frame.
func RateControlFrame(agentID string, rule agentgov.RateLimit, count int64) *dpr.ControlFrame {
	return &dpr.ControlFrame{
		FrameKind: dpr.FrameKindRateUpdate,
		AgentID:   agentID,
		Tool:      rule.Tool,
		Window:    rule.Window,
		Count:     count,
		Limit:     rule.Limit,
	}
}

// FormatRateExceeded returns a human-readable denial reason.
func FormatRateExceeded(rule agentgov.RateLimit) string {
	return fmt.Sprintf("rate limit (%s: %d per %s) exceeded", rule.Tool, rule.Limit, rule.Window)
}
