// Package session manages per-agent session state: call counters, history
// ring buffer, and the kill switch. All operations are safe for concurrent
// use. The in-process sync.Map backend is used for MVP; the interface is
// designed to support a Redis-backed implementation as a drop-in replacement.
package session

import (
	"sync"
	"sync/atomic"
	"time"
)

// HistoryEntry is a single entry in the session history ring buffer.
type HistoryEntry struct {
	ToolID    string
	Effect    string
	Timestamp time.Time
}

// State holds runtime state for a single agent session.
type State struct {
	mu        sync.Mutex
	callCount int64
	history   []HistoryEntry
	maxHistory int
	killed    atomic.Bool
}

// NewState creates a new session state with a history buffer of the given size.
func NewState(historySize int) *State {
	if historySize <= 0 {
		historySize = 20
	}
	return &State{maxHistory: historySize}
}

// IncrCallCount atomically increments and returns the new call count.
func (s *State) IncrCallCount() int64 {
	return atomic.AddInt64(&s.callCount, 1)
}

// CallCount returns the current call count.
func (s *State) CallCount() int64 {
	return atomic.LoadInt64(&s.callCount)
}

// RecordHistory adds a completed call to the history ring buffer.
func (s *State) RecordHistory(toolID, effect string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := HistoryEntry{
		ToolID:    toolID,
		Effect:    effect,
		Timestamp: time.Now(),
	}
	s.history = append(s.history, entry)
	if len(s.history) > s.maxHistory {
		s.history = s.history[len(s.history)-s.maxHistory:]
	}
}

// HistoryContains returns true if a call matching toolPattern appeared
// in the history within the last windowSecs seconds.
func (s *State) HistoryContains(toolPattern string, windowSecs int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-time.Duration(windowSecs) * time.Second)
	for _, e := range s.history {
		if e.Timestamp.After(cutoff) && matchPattern(toolPattern, e.ToolID) {
			return true
		}
	}
	return false
}

// History returns a snapshot of the history buffer, newest first.
func (s *State) History() []HistoryEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := make([]HistoryEntry, len(s.history))
	for i, e := range s.history {
		snapshot[len(s.history)-1-i] = e
	}
	return snapshot
}

// Kill atomically sets the kill switch for this agent. All subsequent
// Evaluate calls return DENY before any policy evaluation runs.
func (s *State) Kill() { s.killed.Store(true) }

// IsKilled reports whether the kill switch has been activated.
func (s *State) IsKilled() bool { return s.killed.Load() }

// Manager holds session states for all active agents, keyed by agentID.
type Manager struct {
	mu     sync.RWMutex
	states map[string]*State
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{states: make(map[string]*State)}
}

// Get returns the session state for an agent, creating it if necessary.
func (m *Manager) Get(agentID string) *State {
	m.mu.RLock()
	s, ok := m.states[agentID]
	m.mu.RUnlock()
	if ok {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok = m.states[agentID]; ok {
		return s
	}
	s = NewState(20)
	m.states[agentID] = s
	return s
}

// Kill sets the kill switch for a specific agent.
func (m *Manager) Kill(agentID string) {
	m.Get(agentID).Kill()
}

func matchPattern(pattern, toolID string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(toolID) >= len(prefix) && toolID[:len(prefix)] == prefix
	}
	return pattern == toolID
}
