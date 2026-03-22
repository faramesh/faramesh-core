package callbacks

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
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
	EventType   EventType         `json:"event_type"`
	Timestamp   time.Time         `json:"timestamp"`
	AgentID     string            `json:"agent_id"`
	SessionID   string            `json:"session_id"`
	ToolID      string            `json:"tool_id,omitempty"`
	Effect      string            `json:"effect,omitempty"` // PERMIT, DENY, DEFER, SHADOW
	ReasonCode  string            `json:"reason_code,omitempty"`
	DPRRecordID string            `json:"dpr_record_id,omitempty"`
	DeferToken  string            `json:"defer_token,omitempty"`
	LatencyUS   int64             `json:"latency_us,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"` // safe metadata only
}

// CallbackFunc is the type for lifecycle callback functions.
type CallbackFunc func(ctx context.Context, event DecisionContext)

// CallbackRegistration holds a registered callback.
type CallbackRegistration struct {
	ID       string
	Event    EventType
	Callback CallbackFunc
}

// OnDecisionPayload is emitted from pipeline decision lifecycle.
type OnDecisionPayload struct {
	AgentID    string `json:"agent_id"`
	ToolID     string `json:"tool_id"`
	Effect     string `json:"effect"`
	RuleID     string `json:"rule_id,omitempty"`
	ReasonCode string `json:"reason_code"`
	RecordID   string `json:"record_id"`
}

// Dispatcher defines callback dispatch points used by runtime pipeline code.
type Dispatcher interface {
	FireOnDecision(OnDecisionPayload)
}

type endpointConfig struct {
	URL       string
	TimeoutMS int
}

type httpJob struct {
	url       string
	timeoutMS int
	payload   any
}

// CallbackManager manages lifecycle callbacks with a worker pool and optional
// HTTP dispatchers loaded from policy callbacks config.
type CallbackManager struct {
	mu         sync.RWMutex
	callbacks  map[EventType][]CallbackRegistration
	workers    int
	queue      chan callbackJob
	started    bool
	httpJobs   chan httpJob
	onDecision endpointConfig
	client     *http.Client
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
		httpJobs:  make(chan httpJob, workers*8),
		client:    &http.Client{},
	}
}

// NewFromPolicyCallbacks builds a manager from a policy callbacks config.
// The input is intentionally untyped to avoid hard coupling to policy structs.
func NewFromPolicyCallbacks(policyCallbacks any) *CallbackManager {
	onDecision := endpointFromPolicy(policyCallbacks, "OnDecision", "on_decision")
	if onDecision.URL == "" {
		return nil
	}
	workers := intValue(fieldByName(policyCallbacks, "Workers", "workers"))
	m := NewCallbackManager(workers)
	if onDecision.TimeoutMS <= 0 {
		onDecision.TimeoutMS = 1500
	}
	m.onDecision = onDecision
	m.Start()
	return m
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
		go cm.httpWorker()
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
	close(cm.httpJobs)
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

func (cm *CallbackManager) httpWorker() {
	for job := range cm.httpJobs {
		b, err := json.Marshal(job.payload)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, job.url, bytes.NewReader(b))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		client := cm.client
		if job.timeoutMS > 0 {
			client = &http.Client{Timeout: time.Duration(job.timeoutMS) * time.Millisecond}
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
	}
}

// FireOnDecision dispatches decision lifecycle callbacks asynchronously.
func (cm *CallbackManager) FireOnDecision(payload OnDecisionPayload) {
	if cm == nil {
		return
	}
	event := DecisionContext{
		EventType:   EventDecision,
		Timestamp:   time.Now().UTC(),
		AgentID:     payload.AgentID,
		ToolID:      payload.ToolID,
		Effect:      payload.Effect,
		ReasonCode:  payload.ReasonCode,
		DPRRecordID: payload.RecordID,
	}
	cm.Fire(event)
	if cm.onDecision.URL == "" {
		return
	}
	select {
	case cm.httpJobs <- httpJob{
		url:       cm.onDecision.URL,
		timeoutMS: cm.onDecision.TimeoutMS,
		payload:   payload,
	}:
	default:
		// Queue full is fail-open by design.
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

func endpointFromPolicy(cfg any, upperName, lowerName string) endpointConfig {
	v := fieldByName(cfg, upperName, lowerName)
	if !v.IsValid() {
		return endpointConfig{}
	}
	return endpointConfig{
		URL:       stringValue(fieldByName(v.Interface(), "URL", "url")),
		TimeoutMS: intValue(fieldByName(v.Interface(), "TimeoutMS", "timeout_ms")),
	}
}

func fieldByName(root any, names ...string) reflect.Value {
	if root == nil {
		return reflect.Value{}
	}
	v := reflect.ValueOf(root)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return reflect.Value{}
	}
	for _, n := range names {
		f := v.FieldByName(n)
		if f.IsValid() {
			return f
		}
	}
	return reflect.Value{}
}

func stringValue(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.String {
		return v.String()
	}
	return ""
}

func intValue(v reflect.Value) int {
	if !v.IsValid() {
		return 0
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(v.Uint())
	default:
		return 0
	}
}
