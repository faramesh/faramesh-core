// Package deferwork — DEFER triage and prioritization.
//
// Implements the three-tier DEFER priority system:
//   - Critical: Safety-critical actions (data deletion, billing, auth changes).
//     SLA: 2 min response. Auto-escalate to PagerDuty after 1 min.
//   - High: Sensitive actions (external API calls, file writes).
//     SLA: 5 min response. Auto-escalate to Slack channel after 3 min.
//   - Normal: Standard actions (reads, internal calls).
//     SLA: 15 min response. No auto-escalation, auto-deny on timeout.
package deferwork

import (
	"sort"
	"sync"
	"time"
)

// Priority levels for DEFER triage.
const (
	PriorityCritical = "critical"
	PriorityHigh     = "high"
	PriorityNormal   = "normal"
)

// TriageRule matches a tool pattern to a priority level.
type TriageRule struct {
	ToolPattern string        `yaml:"tool_pattern"` // glob pattern
	Priority    string        `yaml:"priority"`     // critical, high, normal
	SLA         time.Duration `yaml:"sla"`          // max wait before escalation
	AutoDeny    bool          `yaml:"auto_deny"`    // deny on SLA breach (vs. escalate)
	EscalateTo  string        `yaml:"escalate_to"`  // channel name for escalation
}

// TriageConfig holds the triage rules and defaults.
type TriageConfig struct {
	Rules          []TriageRule  `yaml:"rules"`
	DefaultSLA     time.Duration `yaml:"default_sla"`
	DefaultPriority string      `yaml:"default_priority"`
}

// Triage manages DEFER prioritization, SLA enforcement, and auto-escalation.
type Triage struct {
	mu          sync.RWMutex
	config      TriageConfig
	pending     []*TriagedItem
	escalations chan EscalationEvent
}

// TriagedItem is a DEFER item with triage metadata.
type TriagedItem struct {
	Token      string    `json:"token"`
	AgentID    string    `json:"agent_id"`
	ToolID     string    `json:"tool_id"`
	Reason     string    `json:"reason"`
	Priority   string    `json:"priority"`
	SLA        time.Duration `json:"sla"`
	CreatedAt  time.Time `json:"created_at"`
	Deadline   time.Time `json:"deadline"`
	EscalateAt time.Time `json:"escalate_at"`
	EscalateTo string    `json:"escalate_to"`
	AutoDeny   bool      `json:"auto_deny"`
	Escalated  bool      `json:"escalated"`
}

// EscalationEvent is emitted when a DEFER breaches its SLA.
type EscalationEvent struct {
	Item     *TriagedItem
	Reason   string // "sla_breach"
	Channel  string // target channel
}

// NewTriage creates a new triage manager.
func NewTriage(cfg TriageConfig) *Triage {
	if cfg.DefaultSLA == 0 {
		cfg.DefaultSLA = 15 * time.Minute
	}
	if cfg.DefaultPriority == "" {
		cfg.DefaultPriority = PriorityNormal
	}
	return &Triage{
		config:      cfg,
		escalations: make(chan EscalationEvent, 100),
	}
}

// Classify determines the priority and SLA for a DEFER based on rules.
func (t *Triage) Classify(token, agentID, toolID, reason string) *TriagedItem {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	priority := t.config.DefaultPriority
	sla := t.config.DefaultSLA
	autoDeny := true
	escalateTo := ""

	// Find the first matching rule.
	for _, rule := range t.config.Rules {
		if matchToolGlob(rule.ToolPattern, toolID) {
			priority = rule.Priority
			if rule.SLA > 0 {
				sla = rule.SLA
			}
			autoDeny = rule.AutoDeny
			escalateTo = rule.EscalateTo
			break
		}
	}

	// Override SLA based on priority defaults if not set by rule.
	if sla == t.config.DefaultSLA {
		switch priority {
		case PriorityCritical:
			sla = 2 * time.Minute
		case PriorityHigh:
			sla = 5 * time.Minute
		}
	}

	item := &TriagedItem{
		Token:      token,
		AgentID:    agentID,
		ToolID:     toolID,
		Reason:     reason,
		Priority:   priority,
		SLA:        sla,
		CreatedAt:  now,
		Deadline:   now.Add(sla),
		EscalateAt: now.Add(sla * 2 / 3), // escalate at 2/3 of SLA
		EscalateTo: escalateTo,
		AutoDeny:   autoDeny,
	}

	t.mu.Lock()
	t.pending = append(t.pending, item)
	t.mu.Unlock()

	return item
}

// PendingSorted returns all pending items sorted by priority (critical first).
func (t *Triage) PendingSorted() []*TriagedItem {
	t.mu.RLock()
	defer t.mu.RUnlock()
	items := make([]*TriagedItem, len(t.pending))
	copy(items, t.pending)
	sort.Slice(items, func(i, j int) bool {
		return priorityOrder(items[i].Priority) < priorityOrder(items[j].Priority)
	})
	return items
}

// Remove removes a resolved item from the triage queue.
func (t *Triage) Remove(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, item := range t.pending {
		if item.Token == token {
			t.pending = append(t.pending[:i], t.pending[i+1:]...)
			return
		}
	}
}

// CheckEscalations scans pending items and fires escalation events.
// Should be called periodically (e.g. every 10s).
func (t *Triage) CheckEscalations() []EscalationEvent {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var events []EscalationEvent

	for _, item := range t.pending {
		if item.Escalated {
			continue
		}
		if now.After(item.EscalateAt) {
			item.Escalated = true
			event := EscalationEvent{
				Item:    item,
				Reason:  "sla_breach",
				Channel: item.EscalateTo,
			}
			events = append(events, event)
			select {
			case t.escalations <- event:
			default:
			}
		}
	}
	return events
}

// Escalations returns the channel for listening to escalation events.
func (t *Triage) Escalations() <-chan EscalationEvent {
	return t.escalations
}

func priorityOrder(p string) int {
	switch p {
	case PriorityCritical:
		return 0
	case PriorityHigh:
		return 1
	case PriorityNormal:
		return 2
	default:
		return 3
	}
}

func matchToolGlob(pattern, toolID string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	n := len(pattern)
	if n > 0 && pattern[n-1] == '*' {
		prefix := pattern[:n-1]
		return len(toolID) >= len(prefix) && toolID[:len(prefix)] == prefix
	}
	return pattern == toolID
}
