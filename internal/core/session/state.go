// Package session manages per-agent session state: call counters, history
// ring buffer, cost accumulators, and the kill switch. All operations are
// safe for concurrent use. The in-process sync.Map backend is used for MVP;
// the interface is designed to support a Redis-backed implementation as a
// drop-in replacement.
package session

import (
	"context"
	"strings"
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
	mu         sync.Mutex
	callCount  int64 // atomic
	history    []HistoryEntry
	maxHistory int
	phase      string
	killed     atomic.Bool

	intentMu           sync.Mutex
	intentClass        string
	intentClassExpires time.Time

	// Cost tracking — session-scoped, resets with session.
	sessionCostMu  sync.Mutex
	sessionCostUSD float64

	// Daily cost — persists across sessions; resets at midnight.
	// In the MVP this is in-memory only. Production uses PostgreSQL.
	dailyCostMu  sync.Mutex
	dailyCostUSD float64
	dailyCostDay string // "2006-01-02" — day the counter applies to

	backend    Backend
	dailyStore DailyCostStore
	agentID    string
	sessionID  string
}

// NewState creates a new session state with a history buffer of the given size.
func NewState(historySize int) *State {
	if historySize <= 0 {
		historySize = 20
	}
	return &State{maxHistory: historySize}
}

// NewStateWithBackend creates a state bound to a backend for externalized
// session persistence (e.g. Redis). Local fields remain as fallback.
func NewStateWithBackend(historySize int, agentID string, backend Backend) *State {
	s := NewState(historySize)
	s.agentID = agentID
	s.backend = backend
	return s
}

// NewStateWithStores creates a state with optional shared backends for
// session counters/history (backend) and daily cost persistence (dailyStore).
func NewStateWithStores(historySize int, agentID string, backend Backend, dailyStore DailyCostStore) *State {
	s := NewStateWithBackend(historySize, agentID, backend)
	s.dailyStore = dailyStore
	return s
}

// IncrCallCount atomically increments and returns the new call count.
func (s *State) IncrCallCount() int64 {
	if s.backend != nil && s.agentID != "" {
		if n, err := s.backend.IncrCallCount(context.Background(), s.agentID, s.sessionID); err == nil {
			return n
		}
	}
	return atomic.AddInt64(&s.callCount, 1)
}

// CallCount returns the current call count.
func (s *State) CallCount() int64 {
	if s.backend != nil && s.agentID != "" {
		if n, err := s.backend.GetCallCount(context.Background(), s.agentID, s.sessionID); err == nil {
			return n
		}
	}
	return atomic.LoadInt64(&s.callCount)
}

// AddCost records a tool call cost in USD against both the session and daily accumulators.
func (s *State) AddCost(costUSD float64) {
	if s.backend != nil && s.agentID != "" {
		if _, _, err := s.backend.AddCost(context.Background(), s.agentID, s.sessionID, costUSD); err == nil {
			return
		}
	}
	today := time.Now().UTC().Format("2006-01-02")

	s.sessionCostMu.Lock()
	s.sessionCostUSD += costUSD
	s.sessionCostMu.Unlock()

	s.dailyCostMu.Lock()
	if s.dailyCostDay != today {
		// New calendar day — reset daily counter.
		s.dailyCostUSD = 0
		s.dailyCostDay = today
	}
	s.dailyCostUSD += costUSD
	s.dailyCostMu.Unlock()
	if s.dailyStore != nil && s.agentID != "" {
		_ = s.dailyStore.AddDailyCost(context.Background(), s.agentID, today, costUSD)
	}
}

// CurrentCostUSD returns the total cost accumulated in this session.
func (s *State) CurrentCostUSD() float64 {
	if s.backend != nil && s.agentID != "" {
		if v, err := s.backend.GetSessionCost(context.Background(), s.agentID, s.sessionID); err == nil {
			return v
		}
	}
	s.sessionCostMu.Lock()
	defer s.sessionCostMu.Unlock()
	return s.sessionCostUSD
}

// DailyCostUSD returns the total cost accumulated today (UTC day).
func (s *State) DailyCostUSD() float64 {
	if s.backend != nil && s.agentID != "" {
		if v, err := s.backend.GetDailyCost(context.Background(), s.agentID); err == nil {
			return v
		}
	}
	if s.dailyStore != nil && s.agentID != "" {
		today := time.Now().UTC().Format("2006-01-02")
		if v, err := s.dailyStore.GetDailyCost(context.Background(), s.agentID, today); err == nil {
			return v
		}
	}
	today := time.Now().UTC().Format("2006-01-02")
	s.dailyCostMu.Lock()
	defer s.dailyCostMu.Unlock()
	if s.dailyCostDay != today {
		return 0 // new day, counter not yet initialized
	}
	return s.dailyCostUSD
}

// RecordHistory adds a completed call to the history ring buffer.
func (s *State) RecordHistory(toolID, effect string) {
	if s.backend != nil && s.agentID != "" {
		entry := HistoryEntry{
			ToolID:    toolID,
			Effect:    effect,
			Timestamp: time.Now(),
		}
		if err := s.backend.RecordHistory(context.Background(), s.agentID, s.sessionID, entry, s.maxHistory); err == nil {
			return
		}
	}
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

// CurrentPhase returns the current workflow phase for this session.
func (s *State) CurrentPhase() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

// EnsurePhase sets an initial phase only if phase is currently empty.
func (s *State) EnsurePhase(phase string) {
	if phase == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == "" {
		s.phase = phase
	}
}

// SetPhase overwrites the current workflow phase for this session.
func (s *State) SetPhase(phase string) {
	if strings.TrimSpace(phase) == "" {
		return
	}
	s.mu.Lock()
	s.phase = strings.TrimSpace(phase)
	s.mu.Unlock()
}

// SetIntentClass stores a cached intent class with a TTL.
// A zero or negative TTL falls back to a safe default.
func (s *State) SetIntentClass(class string, ttl time.Duration) {
	class = strings.ToLower(strings.TrimSpace(class))
	if class == "" {
		return
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s.intentMu.Lock()
	s.intentClass = class
	s.intentClassExpires = time.Now().UTC().Add(ttl)
	s.intentMu.Unlock()
}

// IntentClass returns the currently cached intent class when it is still fresh.
// Expired values are cleared eagerly and reported as empty.
func (s *State) IntentClass(now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.intentMu.Lock()
	defer s.intentMu.Unlock()
	if s.intentClass == "" {
		return ""
	}
	if !s.intentClassExpires.IsZero() && now.After(s.intentClassExpires) {
		s.intentClass = ""
		s.intentClassExpires = time.Time{}
		return ""
	}
	return s.intentClass
}

// History returns a snapshot of the history buffer, newest first.
func (s *State) History() []HistoryEntry {
	if s.backend != nil && s.agentID != "" {
		if entries, err := s.backend.GetHistory(context.Background(), s.agentID, s.sessionID, s.maxHistory); err == nil {
			return entries
		}
	}
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
func (s *State) Kill() {
	s.killed.Store(true)
	if s.backend != nil && s.agentID != "" {
		_ = s.backend.SetKillSwitch(context.Background(), s.agentID)
	}
}

// IsKilled reports whether the kill switch has been activated.
func (s *State) IsKilled() bool {
	if s.backend != nil && s.agentID != "" {
		if killed, err := s.backend.IsKilled(context.Background(), s.agentID); err == nil {
			return killed
		}
	}
	return s.killed.Load()
}

// Reset clears selected session counters/state for this agent.
// Supported counters: all, call_count, session_cost, daily_cost, history, phase, kill_switch.
func (s *State) Reset(counter string) {
	mode := strings.TrimSpace(strings.ToLower(counter))
	if mode == "" {
		mode = "all"
	}
	if mode == "all" || mode == "call_count" {
		atomic.StoreInt64(&s.callCount, 0)
	}
	if mode == "all" || mode == "session_cost" {
		s.sessionCostMu.Lock()
		s.sessionCostUSD = 0
		s.sessionCostMu.Unlock()
	}
	if mode == "all" || mode == "daily_cost" {
		s.dailyCostMu.Lock()
		s.dailyCostUSD = 0
		s.dailyCostDay = ""
		s.dailyCostMu.Unlock()
	}
	if mode == "all" || mode == "history" || mode == "phase" {
		s.mu.Lock()
		if mode == "all" || mode == "history" {
			s.history = nil
		}
		if mode == "all" || mode == "phase" {
			s.phase = ""
		}
		s.mu.Unlock()
	}
	if mode == "all" || mode == "intent_class" {
		s.intentMu.Lock()
		s.intentClass = ""
		s.intentClassExpires = time.Time{}
		s.intentMu.Unlock()
	}
	if mode == "all" || mode == "kill_switch" {
		s.killed.Store(false)
	}
}

// Manager holds session states for all active agents, keyed by agentID.
type Manager struct {
	mu         sync.RWMutex
	states     map[string]*State
	backend    Backend
	dailyStore DailyCostStore
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{states: make(map[string]*State)}
}

// NewManagerWithBackend creates a manager whose per-agent states use an
// external backend (e.g. Redis) for shared counters/history/cost.
func NewManagerWithBackend(backend Backend) *Manager {
	return &Manager{
		states:  make(map[string]*State),
		backend: backend,
	}
}

// NewManagerWithDailyStore creates a manager that persists daily cost totals
// in an external store while keeping session counters local.
func NewManagerWithDailyStore(dailyStore DailyCostStore) *Manager {
	return &Manager{
		states:     make(map[string]*State),
		dailyStore: dailyStore,
	}
}

// NewManagerWithStores creates a manager with both shared session backend
// and daily cost persistence store.
func NewManagerWithStores(backend Backend, dailyStore DailyCostStore) *Manager {
	return &Manager{
		states:     make(map[string]*State),
		backend:    backend,
		dailyStore: dailyStore,
	}
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
	if m.backend != nil {
		s = NewStateWithStores(20, agentID, m.backend, m.dailyStore)
	} else {
		s = NewStateWithStores(20, agentID, nil, m.dailyStore)
	}
	m.states[agentID] = s
	return s
}

// Kill sets the kill switch for a specific agent.
func (m *Manager) Kill(agentID string) {
	m.Get(agentID).Kill()
}

// Reset clears selected session counters/state for an agent.
func (m *Manager) Reset(agentID, counter string) {
	m.Get(agentID).Reset(counter)
}

// Count returns the number of active in-memory agent session states.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.states)
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
