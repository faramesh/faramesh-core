package deferwork

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	backendstore "github.com/faramesh/faramesh-core/internal/core/defer/backends"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestResolveReturnsConflictAfterFirstWinner(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithToken("tok-conflict", "agent-a", "tool-a", "needs review")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	if err := w.Resolve("tok-conflict", true, "", "approved"); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}

	err = w.Resolve("tok-conflict", false, "", "deny")
	if err == nil {
		t.Fatalf("expected conflict error from second Resolve()")
	}
	var conflict *ResolveConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected ResolveConflictError, got %T (%v)", err, err)
	}
	if conflict.Code != ResolveConflictCode {
		t.Fatalf("conflict code = %q, want %q", conflict.Code, ResolveConflictCode)
	}
	if conflict.Status != StatusApproved {
		t.Fatalf("conflict status = %q, want %q", conflict.Status, StatusApproved)
	}

	st, pending := w.Status("tok-conflict")
	if pending {
		t.Fatalf("status should not be pending after resolution")
	}
	if st != StatusApproved {
		t.Fatalf("status = %q, want %q", st, StatusApproved)
	}

	res, ok := Wait(h)
	if !ok {
		t.Fatalf("wait ok = false, want true")
	}
	if res.Status != StatusApproved {
		t.Fatalf("resolution status = %q, want %q", res.Status, StatusApproved)
	}
}

func TestResolveConcurrentApproveDenyOnlyOneSucceeds(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithToken("tok-race", "agent-r", "tool-r", "race")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	type outcome struct {
		approved bool
		err      error
	}
	out := make(chan outcome, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		out <- outcome{approved: true, err: w.Resolve("tok-race", true, "", "approve")}
	}()
	go func() {
		defer wg.Done()
		<-start
		out <- outcome{approved: false, err: w.Resolve("tok-race", false, "", "deny")}
	}()

	close(start)
	wg.Wait()
	close(out)

	var winnerApproved bool
	successes := 0
	conflicts := 0
	for o := range out {
		if o.err == nil {
			successes++
			winnerApproved = o.approved
			continue
		}
		var conflict *ResolveConflictError
		if errors.As(o.err, &conflict) {
			conflicts++
			if conflict.Code != ResolveConflictCode {
				t.Fatalf("conflict code = %q, want %q", conflict.Code, ResolveConflictCode)
			}
			continue
		}
		t.Fatalf("unexpected error type from concurrent resolver: %T (%v)", o.err, o.err)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want exactly 1/1", successes, conflicts)
	}

	res, ok := Wait(h)
	if winnerApproved {
		if !ok || res.Status != StatusApproved {
			t.Fatalf("winner approved, got ok=%v status=%q", ok, res.Status)
		}
	} else {
		if ok || res.Status != StatusDenied {
			t.Fatalf("winner denied, got ok=%v status=%q", ok, res.Status)
		}
	}
}

func TestStatusPendingResolvedAndUnknown(t *testing.T) {
	w := NewWorkflow("")
	_, err := w.DeferWithToken("tok-status", "agent-s", "tool-s", "status")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}
	st, pending := w.Status("tok-status")
	if st != StatusPending || !pending {
		t.Fatalf("status before resolve = (%q, %v), want (%q, true)", st, pending, StatusPending)
	}

	if err := w.Resolve("tok-status", false, "", "denied"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	st, pending = w.Status("tok-status")
	if st != StatusDenied || pending {
		t.Fatalf("status after resolve = (%q, %v), want (%q, false)", st, pending, StatusDenied)
	}

	unknownStatus, unknownPending := w.Status("does-not-exist")
	if unknownStatus != StatusExpired || unknownPending {
		t.Fatalf("unknown status = (%q, %v), want (%q, false)", unknownStatus, unknownPending, StatusExpired)
	}
}

func TestResolveUnknownToken(t *testing.T) {
	w := NewWorkflow("")
	err := w.Resolve("missing-token", true, "", "x")
	if err == nil {
		t.Fatalf("expected error for unknown token")
	}
	if !errors.Is(err, errUnknownDeferToken) {
		t.Fatalf("expected unknown token error, got %T (%v)", err, err)
	}
}

func TestResolveWithModifiedArgsConflictAfterResolution(t *testing.T) {
	w := NewWorkflow("")
	_, err := w.DeferWithToken("tok-modified", "agent-m", "tool-m", "x")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}
	if err := w.ResolveWithModifiedArgs("tok-modified", "approver-1", "edited", map[string]any{"x": 1}); err != nil {
		t.Fatalf("first ResolveWithModifiedArgs() error = %v", err)
	}
	err = w.ResolveWithModifiedArgs("tok-modified", "approver-2", "edited-again", map[string]any{"x": 2})
	if err == nil {
		t.Fatalf("expected conflict error on second ResolveWithModifiedArgs()")
	}
	var conflict *ResolveConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected ResolveConflictError, got %T (%v)", err, err)
	}
	if conflict.Code != ResolveConflictCode {
		t.Fatalf("conflict code = %q, want %q", conflict.Code, ResolveConflictCode)
	}
}

func TestDeferMultiApprovalRequiresDistinctApprovers(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithTokenOpts("tok-multi", "agent-a", "tool-a", "review", DeferOptions{ApprovalsRequired: 2})
	if err != nil {
		t.Fatalf("DeferWithTokenOpts() error = %v", err)
	}
	if err := w.Resolve("tok-multi", true, "alice", "ok"); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	req, got, pending := w.ApprovalProgress("tok-multi")
	if !pending || req != 2 || got != 1 {
		t.Fatalf("ApprovalProgress = (%d,%d,pending=%v), want (2,1,true)", req, got, pending)
	}
	select {
	case r := <-h.ch:
		t.Fatalf("channel should not receive until second approval, got %+v", r)
	default:
	}
	if err := w.Resolve("tok-multi", true, "bob", "also ok"); err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	res, ok := Wait(h)
	if !ok || res.Status != StatusApproved {
		t.Fatalf("Wait() ok=%v status=%q", ok, res.Status)
	}
	if !strings.Contains(res.ApproverID, "alice") || !strings.Contains(res.ApproverID, "bob") {
		t.Fatalf("ApproverID = %q, want both alice and bob", res.ApproverID)
	}
	if !strings.Contains(res.Reason, "alice") || !strings.Contains(res.Reason, "bob") {
		t.Fatalf("Reason = %q", res.Reason)
	}
}

func TestDeferMultiApprovalDenyIsImmediate(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithTokenOpts("tok-deny-multi", "a", "t", "r", DeferOptions{ApprovalsRequired: 3})
	if err != nil {
		t.Fatalf("DeferWithTokenOpts() error = %v", err)
	}
	if err := w.Resolve("tok-deny-multi", true, "alice", "ok"); err != nil {
		t.Fatalf("Resolve approve: %v", err)
	}
	if err := w.Resolve("tok-deny-multi", false, "carol", "no"); err != nil {
		t.Fatalf("Resolve deny: %v", err)
	}
	res, ok := Wait(h)
	if ok || res.Status != StatusDenied {
		t.Fatalf("Wait() ok=%v status=%q", ok, res.Status)
	}
}

func TestDeferMultiApprovalSameApproverDoesNotAdvance(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithTokenOpts("tok-same", "a", "t", "r", DeferOptions{ApprovalsRequired: 2})
	if err != nil {
		t.Fatalf("DeferWithTokenOpts() error = %v", err)
	}
	if err := w.Resolve("tok-same", true, "alice", "one"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := w.Resolve("tok-same", true, "alice", "two"); err != nil {
		t.Fatalf("second Resolve same approver: %v", err)
	}
	_, got, _ := w.ApprovalProgress("tok-same")
	if got != 1 {
		t.Fatalf("signoffs = %d, want 1", got)
	}
	select {
	case r := <-h.ch:
		t.Fatalf("unexpected resolution %+v", r)
	default:
	}
}

func TestResolveWithModifiedArgsRejectsMultiApproval(t *testing.T) {
	w := NewWorkflow("")
	if _, err := w.DeferWithTokenOpts("tok-cond", "a", "t", "r", DeferOptions{ApprovalsRequired: 2}); err != nil {
		t.Fatalf("DeferWithTokenOpts: %v", err)
	}
	err := w.ResolveWithModifiedArgs("tok-cond", "x", "y", map[string]any{"k": 1})
	if err == nil {
		t.Fatal("expected error for multi-approval defer with modified args")
	}
}

func TestResolveCapturesApproverIdentity(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithToken("tok-approver", "agent-a", "tool-a", "needs review")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}
	if err := w.Resolve("tok-approver", true, "approver-123", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	res, ok := Wait(h)
	if !ok {
		t.Fatalf("wait ok = false, want true")
	}
	if res.ApproverID != "approver-123" {
		t.Fatalf("approver_id = %q, want approver-123", res.ApproverID)
	}
}

func TestResolveConflictErrorImplementsIsByType(t *testing.T) {
	err := &ResolveConflictError{
		Token:  "tok",
		Code:   ResolveConflictCode,
		Status: StatusApproved,
	}
	if !errors.Is(err, &ResolveConflictError{}) {
		t.Fatalf("errors.Is should match ResolveConflictError by type")
	}
}

func TestResolveConflictEmitsStructuredGovernanceLog(t *testing.T) {
	coreObs, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(coreObs)
	w := NewWorkflow("")
	w.SetLogger(logger)

	_, err := w.DeferWithToken("tok-log-conflict", "agent", "tool", "reason")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}
	if err := w.Resolve("tok-log-conflict", true, "", "approved"); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	_ = w.Resolve("tok-log-conflict", false, "", "denied")

	entries := logs.FilterMessage("defer resolution conflict").All()
	if len(entries) == 0 {
		t.Fatalf("expected defer resolution conflict log entry")
	}
	fields := entries[len(entries)-1].ContextMap()
	if fields["log_schema"] != observe.GovernanceLogSchema {
		t.Fatalf("log_schema=%v", fields["log_schema"])
	}
	if fields["log_schema_version"] != observe.GovernanceLogSchemaVersion {
		t.Fatalf("log_schema_version=%v", fields["log_schema_version"])
	}
	if fields["event"] != observe.EventDeferResolveConflict {
		t.Fatalf("event=%v", fields["event"])
	}
	for _, k := range []string{"defer_token", "conflict_code", "final_status"} {
		if _, ok := fields[k]; !ok {
			t.Fatalf("missing required field %q in defer conflict structured log", k)
		}
	}
}

func TestExpiryCanRaceWithResolveOnlyOneFinalizes(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithToken("tok-exp-race", "agent-e", "tool-e", "x")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	// Force a near-immediate manual expiry attempt in parallel with Resolve.
	var wg sync.WaitGroup
	wg.Add(2)
	var errResolve, errExpire error
	go func() {
		defer wg.Done()
		_, errResolve = w.resolveInternal("tok-exp-race", Resolution{Approved: true, Reason: "a", Status: StatusApproved})
	}()
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond)
		_, errExpire = w.resolveInternal("tok-exp-race", Resolution{Approved: false, Reason: "expired", Status: StatusExpired})
	}()
	wg.Wait()

	// Exactly one should win, the other should conflict.
	if (errResolve == nil) == (errExpire == nil) {
		t.Fatalf("expected exactly one nil error, got resolve=%v expire=%v", errResolve, errExpire)
	}

	res, _ := Wait(h)
	st, pending := w.Status("tok-exp-race")
	if pending {
		t.Fatalf("token should not remain pending")
	}
	if res.Status != st {
		t.Fatalf("wait/status mismatch: wait=%q status=%q", res.Status, st)
	}
}

func TestLateResolveAfterTimeoutKeepsExpiredTerminalState(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithToken("tok-timeout-late", "agent-t", "tool-t", "timeout")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	if _, err := w.resolveInternal("tok-timeout-late", Resolution{Approved: false, Reason: "expired", Status: StatusExpired}); err != nil {
		t.Fatalf("resolveInternal() timeout winner error = %v", err)
	}

	for _, tc := range []struct {
		name     string
		approved bool
		reason   string
	}{
		{name: "late-approve", approved: true, reason: "late approve"},
		{name: "late-deny", approved: false, reason: "late deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := w.Resolve("tok-timeout-late", tc.approved, "", tc.reason)
			if err == nil {
				t.Fatalf("expected conflict for %s", tc.name)
			}
			var conflict *ResolveConflictError
			if !errors.As(err, &conflict) {
				t.Fatalf("expected ResolveConflictError for %s, got %T (%v)", tc.name, err, err)
			}
			if conflict.Code != ResolveConflictCode {
				t.Fatalf("conflict code = %q, want %q", conflict.Code, ResolveConflictCode)
			}
			if conflict.Status != StatusExpired {
				t.Fatalf("conflict status = %q, want %q", conflict.Status, StatusExpired)
			}
		})
	}

	res, ok := Wait(h)
	if ok {
		t.Fatalf("wait ok = true, want false for expired resolution")
	}
	if res.Status != StatusExpired {
		t.Fatalf("resolution status = %q, want %q", res.Status, StatusExpired)
	}

	st, pending := w.Status("tok-timeout-late")
	if pending {
		t.Fatalf("token should not remain pending after timeout finalization")
	}
	if st != StatusExpired {
		t.Fatalf("status = %q, want %q", st, StatusExpired)
	}
}

func TestResolveStressOnlyOneWinnerMaintainsStableFinalState(t *testing.T) {
	w := NewWorkflow("")
	h, err := w.DeferWithToken("tok-stress", "agent-s", "tool-s", "stress")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	const workers = 128
	start := make(chan struct{})
	out := make(chan error, workers)

	for i := 0; i < workers; i++ {
		approve := i%2 == 0
		reason := "deny"
		if approve {
			reason = "approve"
		}
		go func(approved bool, r string) {
			<-start
			out <- w.Resolve("tok-stress", approved, "", r)
		}(approve, reason)
	}

	close(start)

	successes := 0
	conflicts := 0
	conflictStatuses := make([]DeferStatus, 0, workers)
	for i := 0; i < workers; i++ {
		err := <-out
		if err == nil {
			successes++
			continue
		}
		var conflict *ResolveConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("unexpected error type from stress resolver: %T (%v)", err, err)
		}
		if conflict.Code != ResolveConflictCode {
			t.Fatalf("conflict code = %q, want %q", conflict.Code, ResolveConflictCode)
		}
		conflicts++
		conflictStatuses = append(conflictStatuses, conflict.Status)
	}

	if successes != 1 {
		t.Fatalf("successes = %d, want 1", successes)
	}
	if conflicts != workers-1 {
		t.Fatalf("conflicts = %d, want %d", conflicts, workers-1)
	}

	res, ok := Wait(h)
	if (res.Status == StatusApproved) != ok {
		t.Fatalf("wait approval mismatch: status=%q ok=%v", res.Status, ok)
	}

	st, pending := w.Status("tok-stress")
	if pending {
		t.Fatalf("token should not remain pending after stress resolve race")
	}
	if st != res.Status {
		t.Fatalf("final status mismatch: wait=%q status=%q", res.Status, st)
	}

	for _, conflictStatus := range conflictStatuses {
		if conflictStatus != st {
			t.Fatalf("conflict status = %q, want final status %q", conflictStatus, st)
		}
	}
}

func TestDeferWithTokenUsesAutoDenyDeadlineFromTriage(t *testing.T) {
	w := NewWorkflow("")
	w.SetTriage(NewTriage(TriageConfig{
		Rules: []TriageRule{
			{
				ToolPattern:   "payments/*",
				Priority:      PriorityCritical,
				SLA:           5 * time.Minute,
				AutoDeny:      true,
				AutoDenyAfter: 2 * time.Minute,
			},
		},
	}))

	h, err := w.DeferWithToken("tok-auto-deny", "agent-p", "payments/refund", "needs review")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	if got := h.Deadline.Sub(h.CreatedAt); got < 119*time.Second || got > 121*time.Second {
		t.Fatalf("deadline delta = %v, want about 2m", got)
	}
}

func TestWorkflowBackendSyncsCrossInstanceResolution(t *testing.T) {
	backend := backendstore.NewPollingBackend()

	creator := NewWorkflow("")
	creator.SetBackend(backend)

	resolver := NewWorkflow("")
	resolver.SetBackend(backend)

	h, err := creator.DeferWithToken("tok-backend", "agent-a", "tool-a", "review")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}

	pending := resolver.Pending()
	if len(pending) != 1 || pending[0]["token"] != "tok-backend" {
		t.Fatalf("resolver pending = %#v, want tok-backend", pending)
	}

	if err := resolver.Resolve("tok-backend", true, "approver-123", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	res, ok := Wait(h)
	if !ok {
		t.Fatalf("wait ok = false, want true")
	}
	if res.ApproverID != "approver-123" || res.Status != StatusApproved {
		t.Fatalf("wait resolution = %#v, want approved by approver-123", res)
	}

	st, stillPending := creator.Status("tok-backend")
	if stillPending || st != StatusApproved {
		t.Fatalf("creator status = (%q, %v), want approved false", st, stillPending)
	}
}

func TestResolveSignsApprovalEnvelope(t *testing.T) {
	w := NewWorkflow("")
	w.SetApprovalHMACKey([]byte("approval-secret"))

	h, err := w.DeferWithToken("tok-envelope", "agent-a", "tool-a", "review")
	if err != nil {
		t.Fatalf("DeferWithToken() error = %v", err)
	}
	if err := w.Resolve("tok-envelope", true, "approver-9", "approved"); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	res, ok := Wait(h)
	if !ok {
		t.Fatalf("wait ok = false, want true")
	}
	if res.Envelope == nil || res.Envelope.Signature == "" {
		t.Fatalf("expected signed approval envelope, got %#v", res.Envelope)
	}
	if err := VerifyApprovalEnvelope([]byte("approval-secret"), res.Envelope); err != nil {
		t.Fatalf("VerifyApprovalEnvelope() error = %v", err)
	}
}

func TestRestoreResolutionSeedsApprovalEnvelope(t *testing.T) {
	w := NewWorkflow("")
	env := &ApprovalEnvelope{
		Token:      "tok-original",
		ApproverID: "approver-7",
		Approved:   true,
		Reason:     "approved offline",
		Status:     StatusApproved,
		ResolvedAt: time.Now().UTC(),
		Signature:  "deadbeef",
	}
	if err := w.RestoreResolution("tok-replay", Resolution{
		Approved:   true,
		ApproverID: env.ApproverID,
		Reason:     env.Reason,
		Status:     env.Status,
		ResolvedAt: env.ResolvedAt,
		Envelope:   env,
	}); err != nil {
		t.Fatalf("RestoreResolution() error = %v", err)
	}

	got, ok := w.ApprovalEnvelope("tok-replay")
	if !ok {
		t.Fatal("expected restored approval envelope to be available")
	}
	if got.Token != "tok-original" {
		t.Fatalf("restored envelope token = %q, want tok-original", got.Token)
	}
	if got.Signature != "deadbeef" {
		t.Fatalf("restored envelope signature = %q, want deadbeef", got.Signature)
	}

	st, pending := w.Status("tok-replay")
	if pending || st != StatusApproved {
		t.Fatalf("restored status = (%q, %v), want approved false", st, pending)
	}
}
