// Package deferwork implements the DEFER workflow: suspending a tool call
// pending human approval, routing the approval request to a channel
// (Slack, terminal, webhook), and resuming the caller when resolved.
package deferwork

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
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

// Workflow manages all pending DEFER handles for a daemon instance.
type Workflow struct {
	mu       sync.Mutex
	pending  map[string]*Handle
	resolved map[string]*resolvedHandle // keeps last N resolved for status queries
	slackURL string
}

// NewWorkflow creates a new DEFER workflow manager.
// slackWebhookURL may be empty to disable Slack notifications.
func NewWorkflow(slackWebhookURL string) *Workflow {
	return &Workflow{
		pending:  make(map[string]*Handle),
		resolved: make(map[string]*resolvedHandle),
		slackURL: slackWebhookURL,
	}
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

	// Start expiry goroutine.
	go func() {
		select {
		case <-time.After(time.Until(h.Deadline)):
			res := Resolution{Approved: false, Reason: "expired", Status: StatusExpired}
			w.mu.Lock()
			delete(w.pending, token)
			w.resolved[token] = &resolvedHandle{resolution: res}
			w.mu.Unlock()
			select {
			case h.ch <- res:
			default:
			}
		case <-h.ch:
		}
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
	w.mu.Lock()
	h, ok := w.pending[token]
	if ok {
		delete(w.pending, token)
	}
	w.mu.Unlock()

	if !ok {
		return fmt.Errorf("unknown or already-resolved defer token %q", token)
	}

	status := StatusDenied
	if approved {
		status = StatusApproved
	}
	res := Resolution{Approved: approved, Reason: reason, Status: status}

	w.mu.Lock()
	w.resolved[token] = &resolvedHandle{resolution: res}
	w.mu.Unlock()

	select {
	case h.ch <- res:
		return nil
	default:
		return fmt.Errorf("defer token %q already resolved", token)
	}
}

// ResolveWithModifiedArgs approves a DEFER with modified arguments.
// The modified args should be re-validated against the policy before execution.
func (w *Workflow) ResolveWithModifiedArgs(token string, reason string, modifiedArgs map[string]any) error {
	w.mu.Lock()
	h, ok := w.pending[token]
	if ok {
		delete(w.pending, token)
	}
	w.mu.Unlock()

	if !ok {
		return fmt.Errorf("unknown or already-resolved defer token %q", token)
	}

	res := Resolution{
		Approved:     true,
		Reason:       reason,
		Status:       StatusApproved,
		ModifiedArgs: modifiedArgs,
	}

	w.mu.Lock()
	w.resolved[token] = &resolvedHandle{resolution: res}
	w.mu.Unlock()

	select {
	case h.ch <- res:
		return nil
	default:
		return fmt.Errorf("defer token %q already resolved", token)
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
	msg := map[string]any{
		"text": fmt.Sprintf(
			"*Faramesh DEFER* | Agent: `%s` | Tool: `%s`\n>%s\n\nToken: `%s` | Expires: %s\n\nApprove: `faramesh agent approve %s`\nDeny:    `faramesh agent deny %s`",
			h.AgentID, h.ToolID, h.Reason, h.Token,
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
