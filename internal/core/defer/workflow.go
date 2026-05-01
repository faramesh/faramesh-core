// Package deferwork implements the DEFER workflow: suspending a tool call
// pending human approval, routing the approval request to a channel
// (Slack, terminal, webhook), and resuming the caller when resolved.
package deferwork

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	backendstore "github.com/faramesh/faramesh-core/internal/core/defer/backends"
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
	StatusUnknown  DeferStatus = "unknown"

	maxResolvedRetention = 4096
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

	approvalsRequired int
	signOffs          map[string]string
	finalizeStarted   bool

	// Cascade tracking fields (for R4-T DEFER cascade enhancement)
	// ParentDeferToken is set if this DEFER was triggered by another DEFER cascade.
	ParentDeferToken string

	// CascadeReason explains why this DEFER was triggered by a cascade.
	// E.g., "policy_changed", "elevated_routing", "toctou_re_evaluation".
	CascadeReason string

	// CascadeDepth tracks how deeply nested this DEFER is (0 = original, 1 = first cascade, etc.).
	CascadeDepth int

	// CascadePath contains the full lineage of DEFER tokens from origin.
	CascadePath []string
}

// DeferOptions configures registration of a deferred call.
type DeferOptions struct {
	// ApprovalsRequired is how many distinct non-empty approver_ids must
	// approve before the defer completes. Values below 2 behave like 1.
	ApprovalsRequired int
}

// Resolution is the outcome of a resolved DEFER.
type Resolution struct {
	Approved     bool
	ApproverID   string
	Reason       string
	Status       DeferStatus
	ResolvedAt   time.Time
	ModifiedArgs map[string]any // conditional approval: modified args to re-validate
	Envelope     *ApprovalEnvelope
}

// ApprovalEnvelope is a tamper-evident approval record signed with the daemon's HMAC key.
type ApprovalEnvelope struct {
	Token        string         `json:"token"`
	ApproverID   string         `json:"approver_id,omitempty"`
	Approved     bool           `json:"approved"`
	Reason       string         `json:"reason,omitempty"`
	Status       DeferStatus    `json:"status"`
	ResolvedAt   time.Time      `json:"resolved_at"`
	ModifiedArgs map[string]any `json:"modified_args,omitempty"`
	Signature    string         `json:"signature"`
}

// GetCascadeMetrics returns statistics about this cascade chain.
func (h *Handle) GetCascadeMetrics() map[string]any {
	return map[string]any{
		"depth":           h.CascadeDepth,
		"total_in_chain":  len(h.CascadePath) + 1,
		"has_parent":      h.ParentDeferToken != "",
		"reason":          h.CascadeReason,
		"parent_token":    h.ParentDeferToken,
	}
}

// IsInCascade returns true if this DEFER is part of a cascade chain (not the original).
func (h *Handle) IsInCascade() bool {
	return h.ParentDeferToken != ""
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
	resolvedOrder       []string
	slackURL            string
	log                 *zap.Logger
	pagerDutyRoutingKey string
	triage              *Triage
	backend             backendstore.Backend
	contexts            *DeferContextStore
	approvalHMACKey     []byte
}

// NewWorkflow creates a new DEFER workflow manager.
// slackWebhookURL may be empty to disable Slack notifications.
func NewWorkflow(slackWebhookURL string) *Workflow {
	w := &Workflow{
		pending:  make(map[string]*Handle),
		resolved: make(map[string]*resolvedHandle),
		slackURL: slackWebhookURL,
		log:      zap.NewNop(),
		contexts: NewDeferContextStore(),
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

// SetBackend wires a durable backend for cross-instance DEFER state.
func (w *Workflow) SetBackend(backend backendstore.Backend) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.backend = backend
}

// SetApprovalHMACKey configures the key used to sign approval envelopes.
func (w *Workflow) SetApprovalHMACKey(key []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(key) == 0 {
		w.approvalHMACKey = nil
		return
	}
	w.approvalHMACKey = append([]byte(nil), key...)
}

// StoreContext saves the defer context snapshot for later resume validation.
func (w *Workflow) StoreContext(ctx *DeferContext) {
	if ctx == nil || w.contexts == nil {
		return
	}
	w.contexts.Store(ctx)
}

// Context returns the stored defer context for a token, if present.
func (w *Workflow) Context(token string) *DeferContext {
	if w.contexts == nil {
		return nil
	}
	return w.contexts.Get(token)
}

// ApprovalEnvelope returns the signed approval envelope for a resolved token, if present.
func (w *Workflow) ApprovalEnvelope(token string) (*ApprovalEnvelope, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if resolved, ok := w.resolved[token]; ok && resolved.resolution.Envelope != nil {
		return resolved.resolution.Envelope, true
	}
	return nil, false
}

// RestoreResolution seeds a resolved DEFER state without requiring a pending
// handle. This is used by offline replay to reconstruct approved/denied state
// from durable evidence and then exercise the normal resume validation path.
func (w *Workflow) RestoreResolution(token string, res Resolution) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("restore resolution: token is required")
	}
	res = w.normalizeResolution(token, res)
	if res.Envelope == nil {
		return fmt.Errorf("restore resolution: approval envelope is required")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.pending, token)
	w.storeResolvedLocked(token, res)
	return nil
}

// DeferWithToken creates a new deferred handle with a specific token.
// If a handle with this token already exists, the existing handle is returned
// and no duplicate is created. This prevents double-registration when the
// pipeline calls DeferWithToken with a deterministic token.
func (w *Workflow) DeferWithToken(token, agentID, toolID, reason string) (*Handle, error) {
	return w.DeferWithTokenOpts(token, agentID, toolID, reason, DeferOptions{})
}

// DeferWithTokenOpts is like DeferWithToken but applies DeferOptions (for example
// multi-approver defers). The first successful registration wins; later calls
// with the same token return the existing handle unchanged.
func (w *Workflow) DeferWithTokenOpts(token, agentID, toolID, reason string, opts DeferOptions) (*Handle, error) {
	req := opts.ApprovalsRequired
	if req < 1 {
		req = 1
	}

	w.mu.Lock()
	if h, ok := w.pending[token]; ok {
		w.mu.Unlock()
		return h, nil // already exists — idempotent
	}

	h := &Handle{
		Token:             token,
		AgentID:           agentID,
		ToolID:            toolID,
		Reason:            reason,
		CreatedAt:         time.Now(),
		Deadline:          time.Now().Add(DefaultTimeout),
		ch:                make(chan Resolution, 1),
		approvalsRequired: req,
	}
	w.pending[token] = h
	w.mu.Unlock()

	priority := PriorityNormal
	if w.triage != nil {
		if item := w.triage.Classify(token, agentID, toolID, reason); item != nil {
			priority = item.Priority
			if item.AutoDenyAfter > 0 {
				h.Deadline = h.CreatedAt.Add(item.AutoDenyAfter)
			}
		}
	}

	if w.backend != nil {
		if err := w.backend.Enqueue(context.Background(), w.backendItemFromHandle(h, priority)); err != nil {
			w.mu.Lock()
			delete(w.pending, token)
			w.mu.Unlock()
			return nil, err
		}
		go w.awaitBackendResolution(h)
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
func (w *Workflow) Resolve(token string, approved bool, approverID, reason string) error {
	if !approved {
		res := Resolution{Approved: false, ApproverID: approverID, Reason: reason, Status: StatusDenied}
		_, err := w.resolveInternal(token, res)
		return err
	}

	w.mu.Lock()
	h, ok := w.pending[token]
	if !ok {
		w.mu.Unlock()
		res := Resolution{Approved: true, ApproverID: approverID, Reason: reason, Status: StatusApproved}
		_, err := w.resolveInternal(token, res)
		return err
	}
	req := h.approvalsRequired
	if req < 1 {
		req = 1
	}
	if req == 1 {
		w.mu.Unlock()
		res := Resolution{Approved: true, ApproverID: approverID, Reason: reason, Status: StatusApproved}
		_, err := w.resolveInternal(token, res)
		return err
	}

	aid := strings.TrimSpace(approverID)
	if aid == "" {
		w.mu.Unlock()
		return fmt.Errorf("defer approval requires non-empty approver_id when approvals_required=%d", req)
	}
	if h.signOffs == nil {
		h.signOffs = make(map[string]string)
	}
	h.signOffs[aid] = strings.TrimSpace(reason)
	if len(h.signOffs) < req {
		w.mu.Unlock()
		return nil
	}
	if h.finalizeStarted {
		w.mu.Unlock()
		return nil
	}
	h.finalizeStarted = true
	mergedApprovers, mergedReason := mergedApprovalFields(h.signOffs, req)
	w.mu.Unlock()

	res := Resolution{Approved: true, ApproverID: mergedApprovers, Reason: mergedReason, Status: StatusApproved}
	_, err := w.resolveInternal(token, res)
	return err
}

func mergedApprovalFields(signOffs map[string]string, required int) (approverCSV, mergedReason string) {
	keys := make([]string, 0, len(signOffs))
	for k := range signOffs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if len(keys) > required {
		keys = keys[:required]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		r := strings.TrimSpace(signOffs[k])
		if r == "" {
			parts = append(parts, k)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s", k, r))
	}
	return strings.Join(keys, ","), strings.Join(parts, "; ")
}

// ApprovalProgress reports multi-approver progress for a pending token.
// If the token is not pending, pending is false.
func (w *Workflow) ApprovalProgress(token string) (required, received int, pending bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	h, ok := w.pending[token]
	if !ok {
		return 0, 0, false
	}
	req := h.approvalsRequired
	if req < 1 {
		req = 1
	}
	return req, len(h.signOffs), true
}

// ResolveWithModifiedArgs approves a DEFER with modified arguments.
// The modified args should be re-validated against the policy before execution.
func (w *Workflow) ResolveWithModifiedArgs(token string, approverID, reason string, modifiedArgs map[string]any) error {
	w.mu.Lock()
	if h, ok := w.pending[token]; ok && h.approvalsRequired > 1 {
		w.mu.Unlock()
		return fmt.Errorf("conditional defer approval (modified args) requires approvals_required=1")
	}
	w.mu.Unlock()

	res := Resolution{
		Approved:     true,
		ApproverID:   approverID,
		Reason:       reason,
		Status:       StatusApproved,
		ModifiedArgs: modifiedArgs,
	}
	_, err := w.resolveInternal(token, res)
	return err
}

func (w *Workflow) resolveInternal(token string, res Resolution) (bool, error) {
	res = w.normalizeResolution(token, res)
	backendResolved := false
	if w.backend != nil {
		if err := w.backend.Resolve(context.Background(), backendResolutionFromResolution(token, res)); err != nil {
			if errors.Is(err, backendstore.ErrAlreadyResolved) {
				observe.EmitGovernanceLog(w.log, zapcore.WarnLevel, "defer resolution conflict", observe.EventDeferResolveConflict,
					zap.String("defer_token", token),
					zap.String("conflict_code", ResolveConflictCode),
					zap.String("final_status", string(res.Status)),
				)
				return false, &ResolveConflictError{Token: token, Code: ResolveConflictCode, Status: res.Status}
			}
			if errors.Is(err, backendstore.ErrUnknownToken) {
				// Fall through to local state; this keeps in-memory mode and
				// mixed transition states working during backend rollout.
			} else {
				return false, err
			}
		} else {
			backendResolved = true
		}
	}

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
		if backendResolved {
			w.storeResolvedLocked(token, res)
			w.mu.Unlock()
			if w.triage != nil {
				w.triage.Remove(token)
			}
			return true, nil
		}
		w.mu.Unlock()
		return false, fmt.Errorf("%w %q", errUnknownDeferToken, token)
	}
	delete(w.pending, token)
	w.storeResolvedLocked(token, res)
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
// Returns: "pending", "approved", "denied", "expired", or "unknown".
func (w *Workflow) Status(token string) (DeferStatus, bool) {
	if w.backend != nil {
		if st, pending, ok := w.statusFromBackend(token); ok {
			return st, pending
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.pending[token]; ok {
		return StatusPending, true
	}
	if r, ok := w.resolved[token]; ok {
		return r.resolution.Status, false
	}
	return StatusUnknown, false
}

// Wait blocks the caller until the DEFER is resolved or expires.
// Returns the Resolution and whether it was approved before the deadline.
func Wait(h *Handle) (Resolution, bool) {
	r := <-h.ch
	return r, r.Status == StatusApproved
}

// Pending returns a snapshot of all pending tokens and their tool/agent info.
func (w *Workflow) Pending() []map[string]string {
	if w.backend != nil {
		if out, ok := w.pendingFromBackend(); ok {
			return out
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]map[string]string, 0, len(w.pending))
	for _, h := range w.pending {
		row := map[string]string{
			"token":    h.Token,
			"agent_id": h.AgentID,
			"tool_id":  h.ToolID,
			"reason":   h.Reason,
			"deadline": h.Deadline.Format(time.RFC3339),
		}
		if h.approvalsRequired > 1 {
			row["approvals_required"] = fmt.Sprintf("%d", h.approvalsRequired)
			row["approvals_received"] = fmt.Sprintf("%d", len(h.signOffs))
		}
		out = append(out, row)
	}
	return out
}

func (w *Workflow) awaitBackendResolution(h *Handle) {
	if h == nil || w.backend == nil {
		return
	}
	ctx, cancel := context.WithDeadline(context.Background(), h.Deadline.Add(5*time.Second))
	defer cancel()
	res, err := w.backend.WaitForResolution(ctx, h.Token)
	if err != nil || res == nil {
		return
	}
	_, _ = w.syncBackendResolution(h.Token, *res)
}

func (w *Workflow) statusFromBackend(token string) (DeferStatus, bool, bool) {
	snap, err := w.backend.Status(context.Background(), token)
	if err != nil || snap == nil {
		return "", false, false
	}
	switch snap.State {
	case "pending":
		return StatusPending, true, true
	case "approved", "denied", "expired":
		if snap.Resolution != nil {
			_, _ = w.syncBackendResolution(token, *snap.Resolution)
		}
		return backendStateToStatus(snap.State), false, true
	default:
		return "", false, false
	}
}

func (w *Workflow) pendingFromBackend() ([]map[string]string, bool) {
	items, err := w.backend.List(context.Background())
	if err != nil {
		return nil, false
	}
	out := make([]map[string]string, 0, len(items))
	for _, item := range items {
		out = append(out, map[string]string{
			"token":    item.Token,
			"agent_id": item.AgentID,
			"tool_id":  item.ToolID,
			"reason":   item.Reason,
			"deadline": item.Deadline.Format(time.RFC3339),
		})
	}
	return out, true
}

func (w *Workflow) syncBackendResolution(token string, backendRes backendstore.DeferResolution) (bool, error) {
	return w.resolveLocalOnly(token, resolutionFromBackend(backendRes))
}

func (w *Workflow) resolveLocalOnly(token string, res Resolution) (bool, error) {
	res = w.normalizeResolution(token, res)
	w.mu.Lock()
	h, pending := w.pending[token]
	if !pending {
		if finalized, resolved := w.resolved[token]; resolved {
			w.mu.Unlock()
			return false, &ResolveConflictError{Token: token, Code: ResolveConflictCode, Status: finalized.resolution.Status}
		}
		w.storeResolvedLocked(token, res)
		w.mu.Unlock()
		if w.triage != nil {
			w.triage.Remove(token)
		}
		return true, nil
	}
	delete(w.pending, token)
	w.storeResolvedLocked(token, res)
	w.mu.Unlock()

	if w.triage != nil {
		w.triage.Remove(token)
	}
	select {
	case h.ch <- res:
		return true, nil
	default:
		return false, &ResolveConflictError{Token: token, Code: ResolveConflictCode, Status: res.Status}
	}
}

func (w *Workflow) backendItemFromHandle(h *Handle, priority string) backendstore.DeferItem {
	return backendstore.DeferItem{
		Token:     h.Token,
		AgentID:   h.AgentID,
		ToolID:    h.ToolID,
		Reason:    h.Reason,
		Priority:  priority,
		CreatedAt: h.CreatedAt,
		Deadline:  h.Deadline,
	}
}

func backendResolutionFromResolution(token string, res Resolution) backendstore.DeferResolution {
	return backendstore.DeferResolution{
		Token:        token,
		Approved:     res.Approved,
		Reason:       res.Reason,
		Status:       string(res.Status),
		ModifiedArgs: res.ModifiedArgs,
		ResolvedBy:   res.ApproverID,
		ResolvedAt:   res.ResolvedAt,
		Signature:    approvalEnvelopeSignature(res.Envelope),
	}
}

func resolutionFromBackend(res backendstore.DeferResolution) Resolution {
	return Resolution{
		Approved:     res.Approved,
		ApproverID:   res.ResolvedBy,
		Reason:       res.Reason,
		Status:       backendStateToStatus(res.Status),
		ResolvedAt:   res.ResolvedAt,
		ModifiedArgs: res.ModifiedArgs,
		Envelope: &ApprovalEnvelope{
			Token:        res.Token,
			ApproverID:   res.ResolvedBy,
			Approved:     res.Approved,
			Reason:       res.Reason,
			Status:       backendStateToStatus(res.Status),
			ResolvedAt:   res.ResolvedAt,
			ModifiedArgs: res.ModifiedArgs,
			Signature:    res.Signature,
		},
	}
}

func (w *Workflow) normalizeResolution(token string, res Resolution) Resolution {
	if res.ResolvedAt.IsZero() {
		res.ResolvedAt = time.Now().UTC()
	}
	if res.Envelope == nil && len(w.approvalHMACKey) > 0 {
		res.Envelope = &ApprovalEnvelope{
			Token:        token,
			ApproverID:   res.ApproverID,
			Approved:     res.Approved,
			Reason:       res.Reason,
			Status:       res.Status,
			ResolvedAt:   res.ResolvedAt,
			ModifiedArgs: res.ModifiedArgs,
			Signature:    signApprovalEnvelope(w.approvalHMACKey, token, res),
		}
	}
	return res
}

func (w *Workflow) storeResolvedLocked(token string, res Resolution) {
	if strings.TrimSpace(token) == "" {
		return
	}
	if _, exists := w.resolved[token]; !exists {
		w.resolvedOrder = append(w.resolvedOrder, token)
	}
	w.resolved[token] = &resolvedHandle{resolution: res}
	if len(w.resolvedOrder) <= maxResolvedRetention {
		return
	}
	overflow := len(w.resolvedOrder) - maxResolvedRetention
	for i := 0; i < overflow; i++ {
		delete(w.resolved, w.resolvedOrder[i])
	}
	trimmed := make([]string, len(w.resolvedOrder)-overflow)
	copy(trimmed, w.resolvedOrder[overflow:])
	w.resolvedOrder = trimmed
}

// VerifyApprovalEnvelope checks the HMAC signature for a signed approval envelope.
func VerifyApprovalEnvelope(key []byte, env *ApprovalEnvelope) error {
	if env == nil {
		return fmt.Errorf("missing approval envelope")
	}
	if len(key) == 0 {
		return fmt.Errorf("approval verification key not configured")
	}
	expected := signApprovalEnvelope(key, env.Token, Resolution{
		Approved:     env.Approved,
		ApproverID:   env.ApproverID,
		Reason:       env.Reason,
		Status:       env.Status,
		ResolvedAt:   env.ResolvedAt,
		ModifiedArgs: env.ModifiedArgs,
	})
	actual, err := hex.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("invalid approval envelope signature encoding")
	}
	want, _ := hex.DecodeString(expected)
	if !hmac.Equal(want, actual) {
		return fmt.Errorf("approval envelope signature verification failed")
	}
	return nil
}

func signApprovalEnvelope(key []byte, token string, res Resolution) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(
		mac,
		"%s|%s|%t|%s|%s|%s|%s",
		token,
		res.ApproverID,
		res.Approved,
		res.Reason,
		res.Status,
		res.ResolvedAt.UTC().Format(time.RFC3339Nano),
		deterministicArgsJSON(res.ModifiedArgs),
	)
	return hex.EncodeToString(mac.Sum(nil))
}

func approvalEnvelopeSignature(env *ApprovalEnvelope) string {
	if env == nil {
		return ""
	}
	return env.Signature
}

func deterministicArgsJSON(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	body, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	return string(body)
}

func backendStateToStatus(state string) DeferStatus {
	switch state {
	case "approved":
		return StatusApproved
	case "denied":
		return StatusDenied
	case "expired":
		return StatusExpired
	default:
		return StatusPending
	}
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
