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

	"github.com/google/uuid"
)

// DefaultTimeout is how long a DEFER waits before auto-expiring.
const DefaultTimeout = 5 * time.Minute

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
	Approved bool
	Reason   string
}

// Workflow manages all pending DEFER handles for a daemon instance.
type Workflow struct {
	mu      sync.Mutex
	pending map[string]*Handle
	slackURL string
}

// NewWorkflow creates a new DEFER workflow manager.
// slackWebhookURL may be empty to disable Slack notifications.
func NewWorkflow(slackWebhookURL string) *Workflow {
	return &Workflow{
		pending:  make(map[string]*Handle),
		slackURL: slackWebhookURL,
	}
}

// Defer creates a new deferred handle, sends the approval notification,
// and returns the token. The caller blocks in Wait() until resolved or expired.
func (w *Workflow) Defer(agentID, toolID, reason string) (*Handle, error) {
	token := uuid.New().String()[:8]
	h := &Handle{
		Token:     token,
		AgentID:   agentID,
		ToolID:    toolID,
		Reason:    reason,
		CreatedAt: time.Now(),
		Deadline:  time.Now().Add(DefaultTimeout),
		ch:        make(chan Resolution, 1),
	}

	w.mu.Lock()
	w.pending[token] = h
	w.mu.Unlock()

	// Start expiry goroutine.
	go func() {
		select {
		case <-time.After(time.Until(h.Deadline)):
			w.mu.Lock()
			delete(w.pending, token)
			w.mu.Unlock()
			select {
			case h.ch <- Resolution{Approved: false, Reason: "expired"}:
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

	select {
	case h.ch <- Resolution{Approved: approved, Reason: reason}:
		return nil
	default:
		return fmt.Errorf("defer token %q already resolved", token)
	}
}

// Status returns the current status of a DEFER token.
func (w *Workflow) Status(token string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.pending[token]
	if !ok {
		return "resolved", false
	}
	return "pending", true
}

// Wait blocks the caller until the DEFER is resolved or expires.
// Returns the Resolution and whether it was before the deadline.
func Wait(h *Handle) (Resolution, bool) {
	r := <-h.ch
	expired := r.Reason == "expired"
	return r, !expired
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
