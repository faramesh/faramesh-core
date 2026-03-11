// Package callbacks — lifecycle callbacks.
//
// Provides hooks for on_decision, on_defer_resolved, on_session_end events.
// Callbacks receive a PII-safe DecisionContext and run in a worker pool.
// Callback invocations are recorded in DPR.
package callbacks

import (
	"context"
	"sync"
	"time"
)

// EventType identifies the lifecycle event.
type EventType string

const (
	EventDecision      EventType = "on_decision"
	EventDeferResolved EventType = "on_defer_resolved"
	EventSessionEnd    EventType = "on_session_end"
)

// DecisionContext is a PII-safe snapshot of a governance decision.
// No raw arguments, user content, or session state values are included.
type DecisionContext struct {
	EventType    EventType         `json:"event_type"`
	Timestamp    time.Time         `json:"timestamp"`
	AgentID      string            `json:"agent_id"`
	SessionID    string            `json:"session_id"`
	ToolID       string            `json:"tool_id,omitempty"`
	Effect       string            `json:"effect,omitempty"` // PERMIT, DENY, DEFER, SHADOW
	ReasonCode   string            `json:"reason_code,omitempty"`
	DPRRecordID  string            `json:"dpr_record_id,omitempty"`
	DeferToken   string            `json:"defer_token,omitempty"`
	LatencyUS    int64             `json:"latency_us,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"` // safe metadata only
}

// CallbackFunc is the type for lifecycle callback functions.
type CallbackFunc func(ctx context.Context, event DecisionContext)

// CallbackRegistration holds a registered callback.
type CallbackRegistration struct {
	ID       string
	Event    EventType
	Callback CallbackFunc
}

// CallbackManager manages lifecycle callbacks with a worker pool.
type CallbackManager struct {
	mu        sync.RWMutex
	callbacks map[EventType][]CallbackRegistration
	workers   int
	queue     chan callbackJob
	done      chan struct{}
	started   bool
}

type callbackJob struct {
	reg   CallbackRegistration
	event DecisionContext
}

// NewCallbackManager creates a callback manager with the given worker count.
func NewCallbackManager(workers int) *CallbackManager {
	if workers <= 0 {
		workers = 4
	}
	return &CallbackManager{
		callbacks: make(map[EventType][]CallbackRegistration),
		workers:   workers,
		queue:     make(chan callbackJob, 1000),
		done:      make(chan struct{}),
	}
}

// Register adds a callback for an event type.
func (cm *CallbackManager) Register(id string, event EventType, fn CallbackFunc) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.callbacks[event] = append(cm.callbacks[event], CallbackRegistration{
		ID:       id,
		Event:    event,
		Callback: fn,
	})
}

// Unregister removes a callback by ID.
func (cm *CallbackManager) Unregister(id string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for event, regs := range cm.callbacks {
		filtered := regs[:0]
		for _, r := range regs {
			if r.ID != id {
				filtered = append(filtered, r)
			}
		}
		cm.callbacks[event] = filtered
	}
}

// Start launches the worker pool.
func (cm *CallbackManager) Start() {
	cm.mu.Lock()
	if cm.started {
		cm.mu.Unlock()
		return
	}
	cm.started = true
	cm.mu.Unlock()

	for i := 0; i < cm.workers; i++ {
		go cm.worker()
	}
}

// Stop drains the queue and stops workers.
func (cm *CallbackManager) Stop() {
	cm.mu.Lock()
	if !cm.started {
		cm.mu.Unlock()
		return
	}
	cm.started = false
	cm.mu.Unlock()
	close(cm.queue)
	// Workers will exit when queue is closed.
}

// Fire dispatches an event to all registered callbacks (async via worker pool).
func (cm *CallbackManager) Fire(event DecisionContext) {
	cm.mu.RLock()
	regs := cm.callbacks[event.EventType]
	cm.mu.RUnlock()

	for _, reg := range regs {
		select {
		case cm.queue <- callbackJob{reg: reg, event: event}:
		default:
			// Queue full, drop event. In production, would record dropped callbacks.
		}
	}
}

func (cm *CallbackManager) worker() {
	for job := range cm.queue {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Catch panics in callbacks.
			defer func() { recover() }()
			job.reg.Callback(ctx, job.event)
		}()
	}
}

// RegisteredCallbacks returns the count of registered callbacks per event type.
func (cm *CallbackManager) RegisteredCallbacks() map[EventType]int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	counts := make(map[EventType]int, len(cm.callbacks))
	for event, regs := range cm.callbacks {
		counts[event] = len(regs)
	}
	return counts
}
