// Package deferwork implements the DEFER workflow: suspending a tool call
// pending human approval, routing the approval request to a channel
// (Slack, terminal, webhook), and resuming the caller when resolved.
package deferwork

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultTimeout is how long a DEFER waits before auto-expiring.
const DefaultTimeout = 5 * time.Minute

// DeferStatus represents the state of a DEFER handle.
type DeferStatus string

const (
	StatusPending  DeferStatus = "pending"
	StatusApproved DeferStatus = "approved"
	StatusDenied   DeferStatus = "denied"
	StatusExpired  DeferStatus = "expired"
)

// Handle represents a pending deferred call.
type Handle struct {
	Token     string
	AgentID   string
	ToolID    string
	Reason    string
	CreatedAt time.Time
	Deadline  time.Time
	ch        chan Resolution
}

// Resolution is the outcome of a resolved DEFER.
type Resolution struct {
	Approved     bool
	Reason       string
	Status       DeferStatus
	ModifiedArgs map[string]any // conditional approval: modified args to re-validate
}

// resolvedHandle stores the final resolution for completed DEFERs so
// Status() can report approved/denied/expired after resolution.
type resolvedHandle struct {
	resolution Resolution
}

// ResolveConflictCode identifies second-and-later resolution attempts
// against a DEFER token that has already been finalized.
const ResolveConflictCode = "DEFER_RESOLUTION_CONFLICT"

// ResolveConflictError is returned when a resolver loses a concurrent race
// and attempts to resolve an already finalized DEFER token.
type ResolveConflictError struct {
	Token  string
	Code   string
	Status DeferStatus
}

func (e *ResolveConflictError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("defer token %q already finalized with status %q (%s)", e.Token, e.Status, e.Code)
}

// Is allows errors.Is(err, &ResolveConflictError{}) to match by type.
func (e *ResolveConflictError) Is(target error) bool {
	_, ok := target.(*ResolveConflictError)
	return ok
}

var errUnknownDeferToken = errors.New("unknown defer token")

// Workflow manages all pending DEFER handles for a daemon instance.
type Workflow struct {
	mu                  sync.Mutex
	pending             map[string]*Handle
	resolved            map[string]*resolvedHandle // keeps last N resolved for status queries
	slackURL            string
	log                 *zap.Logger
	pagerDutyRoutingKey string
	triage              *Triage
}

// NewWorkflow creates a new DEFER workflow manager.
// slackWebhookURL may be empty to disable Slack notifications.
func NewWorkflow(slackWebhookURL string) *Workflow {
	w := &Workflow{
		pending:  make(map[string]*Handle),
		resolved: make(map[string]*resolvedHandle),
		slackURL: slackWebhookURL,
		log:      zap.NewNop(),
	}
	return w
}

// SetLogger sets the workflow logger for structured governance events.
func (w *Workflow) SetLogger(log *zap.Logger) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if log == nil {
		w.log = zap.NewNop()
		return
	}
	w.log = log
}

// SetPagerDutyRoutingKey enables PagerDuty Events v2 escalation for triage events.
func (w *Workflow) SetPagerDutyRoutingKey(routingKey string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pagerDutyRoutingKey = routingKey
}

// SetTriage wires the triage manager and starts escalation polling.
func (w *Workflow) SetTriage(t *Triage) {
	w.mu.Lock()
	w.triage = t
	w.mu.Unlock()
	go w.runEscalationLoop()
}

// DeferWithToken creates a new deferred handle with a specific token.
// If a handle with this token already exists, the existing handle is returned
// and no duplicate is created. This prevents double-registration when the
// pipeline calls DeferWithToken with a deterministic token.
func (w *Workflow) DeferWithToken(token, agentID, toolID, reason string) (*Handle, error) {
	w.mu.Lock()
	if h, ok := w.pending[token]; ok {
		w.mu.Unlock()
		return h, nil // already exists — idempotent
	}

	h := &Handle{
		Token:     token,
		AgentID:   agentID,
		ToolID:    toolID,
		Reason:    reason,
		CreatedAt: time.Now(),
		Deadline:  time.Now().Add(DefaultTimeout),
		ch:        make(chan Resolution, 1),
	}
	w.pending[token] = h
	w.mu.Unlock()

	if w.triage != nil {
		w.triage.Classify(token, agentID, toolID, reason)
	}

	// Start expiry goroutine.
	go func() {
		<-time.After(time.Until(h.Deadline))
		_, _ = w.resolveInternal(token, Resolution{
			Approved: false,
			Reason:   "expired",
			Status:   StatusExpired,
		})
	}()

	if w.slackURL != "" {
		go w.notifySlack(h)
	}

	return h, nil
}

// Defer creates a new deferred handle with a random token.
// Prefer DeferWithToken when a deterministic token is available.
func (w *Workflow) Defer(agentID, toolID, reason string) (*Handle, error) {
	// Generate a unique token from timestamp + tool for demo/test use.
	token := fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	return w.DeferWithToken(token, agentID, toolID, reason)
}

// Resolve approves or denies a pending DEFER by its token.
// Returns an error if the token is unknown or already resolved.
func (w *Workflow) Resolve(token string, approved bool, reason string) error {
	status := StatusDenied
	if approved {
		status = StatusApproved
	}
	res := Resolution{Approved: approved, Reason: reason, Status: status}
	_, err := w.resolveInternal(token, res)
	return err
}

// ResolveWithModifiedArgs approves a DEFER with modified arguments.
// The modified args should be re-validated against the policy before execution.
func (w *Workflow) ResolveWithModifiedArgs(token string, reason string, modifiedArgs map[string]any) error {
	res := Resolution{
		Approved:     true,
		Reason:       reason,
		Status:       StatusApproved,
		ModifiedArgs: modifiedArgs,
	}
	_, err := w.resolveInternal(token, res)
	return err
}

func (w *Workflow) resolveInternal(token string, res Resolution) (bool, error) {
	w.mu.Lock()
	h, pending := w.pending[token]
	if !pending {
		if finalized, resolved := w.resolved[token]; resolved {
			observe.EmitGovernanceLog(w.log, zapcore.WarnLevel, "defer resolution conflict", observe.EventDeferResolveConflict,
				zap.String("defer_token", token),
				zap.String("conflict_code", ResolveConflictCode),
				zap.String("final_status", string(finalized.resolution.Status)),
			)
			w.mu.Unlock()
			return false, &ResolveConflictError{
				Token:  token,
				Code:   ResolveConflictCode,
				Status: finalized.resolution.Status,
			}
		}
		w.mu.Unlock()
		return false, fmt.Errorf("%w %q", errUnknownDeferToken, token)
	}
	delete(w.pending, token)
	w.resolved[token] = &resolvedHandle{resolution: res}
	w.mu.Unlock()

	if w.triage != nil {
		w.triage.Remove(token)
	}

	select {
	case h.ch <- res:
		return true, nil
	default:
		observe.EmitGovernanceLog(w.log, zapcore.WarnLevel, "defer resolution conflict", observe.EventDeferResolveConflict,
			zap.String("defer_token", token),
			zap.String("conflict_code", ResolveConflictCode),
			zap.String("final_status", string(res.Status)),
		)
		return false, &ResolveConflictError{
			Token:  token,
			Code:   ResolveConflictCode,
			Status: res.Status,
		}
	}
}

// Status returns the current detailed status of a DEFER token.
// Returns: "pending", "approved", "denied", or "expired".
func (w *Workflow) Status(token string) (DeferStatus, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.pending[token]; ok {
		return StatusPending, true
	}
	if r, ok := w.resolved[token]; ok {
		return r.resolution.Status, false
	}
	return StatusExpired, false // unknown token treated as expired
}

// Wait blocks the caller until the DEFER is resolved or expires.
// Returns the Resolution and whether it was approved before the deadline.
func Wait(h *Handle) (Resolution, bool) {
	r := <-h.ch
	return r, r.Status == StatusApproved
}

// Pending returns a snapshot of all pending tokens and their tool/agent info.
func (w *Workflow) Pending() []map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]map[string]string, 0, len(w.pending))
	for _, h := range w.pending {
		out = append(out, map[string]string{
			"token":    h.Token,
			"agent_id": h.AgentID,
			"tool_id":  h.ToolID,
			"reason":   h.Reason,
			"deadline": h.Deadline.Format(time.RFC3339),
		})
	}
	return out
}

func (w *Workflow) notifySlack(h *Handle) {
	safeReason := observe.RedactString(h.Reason)
	if safeReason != "" {
		safeReason = "[Context redacted for security. Use `faramesh explain --token` for authorized details.]"
	}
	msg := map[string]any{
		"text": fmt.Sprintf(
			"*Faramesh DEFER* | Agent: `%s` | Tool: `%s`\n>%s\n\nToken: `%s` | Expires: %s\n\nApprove: `faramesh agent approve %s`\nDeny:    `faramesh agent deny %s`",
			h.AgentID, h.ToolID, safeReason, h.Token,
			h.Deadline.Format("15:04:05"),
			h.Token, h.Token,
		),
	}
	body, _ := json.Marshal(msg)
	resp, err := http.Post(w.slackURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (w *Workflow) runEscalationLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		w.mu.Lock()
		t := w.triage
		w.mu.Unlock()
		if t == nil {
			return
		}
		events := t.CheckEscalations()
		for _, ev := range events {
			if ev.Channel == "pagerduty" && w.pagerDutyRoutingKey != "" {
				go w.notifyPagerDuty(ev)
				continue
			}
			if w.slackURL != "" {
				// Reuse Slack path for non-PD or fallback.
				go w.notifySlack(ev.Item.asHandle())
			}
		}
	}
}

func (ti *TriagedItem) asHandle() *Handle {
	return &Handle{
		Token:     ti.Token,
		AgentID:   ti.AgentID,
		ToolID:    ti.ToolID,
		Reason:    ti.Reason,
		CreatedAt: ti.CreatedAt,
		Deadline:  ti.Deadline,
		ch:        make(chan Resolution, 1),
	}
}

func (w *Workflow) notifyPagerDuty(ev EscalationEvent) {
	body := map[string]any{
		"routing_key":  w.pagerDutyRoutingKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":   fmt.Sprintf("Faramesh DEFER SLA breach: %s (%s)", ev.Item.ToolID, ev.Item.Priority),
			"source":    "faramesh-core",
			"severity":  mapPriorityToPDSeverity(ev.Item.Priority),
			"component": "defer-workflow",
			"custom_details": map[string]any{
				"token":      ev.Item.Token,
				"agent_id":   ev.Item.AgentID,
				"tool_id":    ev.Item.ToolID,
				"priority":   ev.Item.Priority,
				"created_at": ev.Item.CreatedAt.Format(time.RFC3339),
				"deadline":   ev.Item.Deadline.Format(time.RFC3339),
			},
		},
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post("https://events.pagerduty.com/v2/enqueue", "application/json", bytes.NewReader(b))
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func mapPriorityToPDSeverity(p string) string {
	switch p {
	case PriorityCritical:
		return "critical"
	case PriorityHigh:
		return "error"
	default:
		return "warning"
	}
}
