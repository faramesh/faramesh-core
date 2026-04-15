// Package deferwork — DeferContext for message history and resume validation.
//
// When a DEFER is approved, the agent needs to resume execution. But the
// context may have changed since the DEFER was created:
//   - Session state may have been modified by other agents
//   - The message history may have diverged
//   - Policy rules may have been updated
//
// DeferContext captures the state at DEFER creation and validates it at
// resume time to ensure the approval is still valid.
package deferwork

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"time"
)

// DeferContext captures the execution context at DEFER creation time.
type DeferContext struct {
	// Token is the DEFER token this context belongs to.
	Token string `json:"token"`

	// SessionID is the session that created the DEFER.
	SessionID string `json:"session_id"`

	// PolicyHash is the hash of the active policy at DEFER time.
	PolicyHash string `json:"policy_hash"`

	// MessageHistory is the last N messages before the DEFER.
	// Used for replay and context validation.
	MessageHistory []Message `json:"message_history,omitempty"`

	// ArgSnapshot captures the original args at DEFER time.
	ArgSnapshot map[string]any `json:"arg_snapshot"`

	// SessionStateHash is a hash of relevant session state keys.
	SessionStateHash string `json:"session_state_hash"`

	// CreatedAt is when this context was captured.
	CreatedAt time.Time `json:"created_at"`

	// PreAuthorizedToken allows pre-approved actions to bypass DEFER.
	// If set, the action was pre-authorized and doesn't need approval.
	PreAuthorizedToken string `json:"pre_authorized_token,omitempty"`
}

// Message represents a conversation message in the DEFER context.
type Message struct {
	Role    string `json:"role"` // user, assistant, system, tool
	Content string `json:"content"`
	ToolID  string `json:"tool_id,omitempty"`
	At      int64  `json:"at"` // unix timestamp
}

// NewDeferContext creates a context snapshot for a DEFER.
func NewDeferContext(token, sessionID, policyHash string, args map[string]any) *DeferContext {
	return &DeferContext{
		Token:       token,
		SessionID:   sessionID,
		PolicyHash:  policyHash,
		ArgSnapshot: args,
		CreatedAt:   time.Now(),
	}
}

// SetMessageHistory records the last N messages.
func (dc *DeferContext) SetMessageHistory(messages []Message, maxMessages int) {
	if len(messages) > maxMessages {
		messages = messages[len(messages)-maxMessages:]
	}
	dc.MessageHistory = messages
}

// SetSessionStateHash computes and stores a hash of session state.
func (dc *DeferContext) SetSessionStateHash(state map[string]any) {
	h := sha256.New()
	keys := make([]string, 0, len(state))
	for k := range state {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := state[k]
		fmt.Fprintf(h, "%s=%v|", k, v)
	}
	dc.SessionStateHash = fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// ValidateContextValidity checks if the context is still valid for resume.
type ContextValidation struct {
	Valid          bool     `json:"valid"`
	Warnings       []string `json:"warnings,omitempty"`
	PolicyChanged  bool     `json:"policy_changed"`
	SessionChanged bool     `json:"session_changed"`
	Expired        bool     `json:"expired"`
}

// ValidateForResume checks if the DEFER context is still valid.
func (dc *DeferContext) ValidateForResume(currentPolicyHash, currentSessionStateHash string, maxAge time.Duration) ContextValidation {
	v := ContextValidation{Valid: true}

	// Check policy hasn't changed.
	if dc.PolicyHash != "" && dc.PolicyHash != currentPolicyHash {
		v.PolicyChanged = true
		v.Warnings = append(v.Warnings, "policy has changed since DEFER was created")
		// Policy change doesn't invalidate — but the resumed action will be
		// re-evaluated against the new policy anyway.
	}

	// Check session state hasn't changed.
	if dc.SessionStateHash != "" && dc.SessionStateHash != currentSessionStateHash {
		v.SessionChanged = true
		v.Warnings = append(v.Warnings, "session state has changed since DEFER was created")
	}

	// Check age.
	if maxAge > 0 && time.Since(dc.CreatedAt) > maxAge {
		v.Expired = true
		v.Valid = false
		v.Warnings = append(v.Warnings, fmt.Sprintf("DEFER context expired (age: %s, max: %s)",
			time.Since(dc.CreatedAt).Round(time.Second), maxAge))
	}

	return v
}

// IsPreAuthorized checks if this action was pre-authorized.
func (dc *DeferContext) IsPreAuthorized() bool {
	return dc.PreAuthorizedToken != ""
}

// DeferContextStore manages DEFER contexts.
type DeferContextStore struct {
	mu       sync.RWMutex
	contexts map[string]*DeferContext // token → context
}

// NewDeferContextStore creates a new context store.
func NewDeferContextStore() *DeferContextStore {
	return &DeferContextStore{
		contexts: make(map[string]*DeferContext),
	}
}

// Store saves a DEFER context.
func (s *DeferContextStore) Store(ctx *DeferContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts[ctx.Token] = ctx
}

// Get retrieves a DEFER context by token.
func (s *DeferContextStore) Get(token string) *DeferContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.contexts[token]
}

// Remove deletes a DEFER context.
func (s *DeferContextStore) Remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contexts, token)
}

// Cleanup removes contexts older than maxAge.
func (s *DeferContextStore) Cleanup(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for token, ctx := range s.contexts {
		if ctx.CreatedAt.Before(cutoff) {
			delete(s.contexts, token)
			removed++
		}
	}
	return removed
}
