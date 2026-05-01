package core

import (
    "testing"
    "time"

    backendstore "github.com/faramesh/faramesh-core/internal/core/defer/backends"
    deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
    "github.com/faramesh/faramesh-core/internal/core/policy"
    "github.com/faramesh/faramesh-core/internal/core/session"
)

func TestPipelineE2E_CascadeBackendPersistence(t *testing.T) {
    policyYAML := `
faramesh_version: "1.0"
agent_id: "agent-a"
default_effect: deny
rules:
  - id: "defer-dangerous"
    tool: "dangerous/run"
    effect: "defer"
    reason: "human approval required"
`
    doc, version, err := policy.LoadBytes([]byte(policyYAML))
    if err != nil {
        t.Fatalf("load policy: %v", err)
    }
    eng, err := policy.NewEngine(doc, version)
    if err != nil {
        t.Fatalf("compile policy: %v", err)
    }

    // Wire workflow with durable polling backend to observe persisted DeferItem
    wf := deferwork.NewWorkflow("")
    pb := backendstore.NewPollingBackend()
    wf.SetBackend(pb)
    key := []byte("approval-secret")
    wf.SetApprovalHMACKey(key)

    p := NewPipeline(Config{
        Engine:   policy.NewAtomicEngine(eng),
        Sessions: session.NewManager(),
        Defers:   wf,
        HMACKey:  key,
    })

    // Create original DEFER via pipeline eval
    first := p.Evaluate(CanonicalActionRequest{
        CallID:    "call-1",
        AgentID:   "agent-a",
        SessionID: "sess-1",
        ToolID:    "dangerous/run",
        Args:      map[string]any{"target": "prod"},
        Timestamp: time.Now(),
    })
    if first.Effect != EffectDefer {
        t.Fatalf("expected first defer, got %s", first.Effect)
    }

    // Create a second DEFER that cascades from the first
    token2 := deterministicDeferToken("call-2", "dangerous/run")
    handle2, err := p.defers.DeferWithTokenOpts(token2, "agent-a", "dangerous/run", "cascade:policy_changed", deferwork.DeferOptions{})
    if err != nil || handle2 == nil {
        t.Fatalf("failed to create second defer handle: %v", err)
    }
    // Link cascade to first token and store context via pipeline helper
    handle2.ParentDeferToken = first.DeferToken
    handle2.CascadeReason = "policy_changed"
    handle2.CascadeDepth = 1
    handle2.CascadePath = []string{first.DeferToken}

    p.storeDeferContext(token2, CanonicalActionRequest{
        CallID:    "call-2",
        AgentID:   "agent-a",
        SessionID: "sess-1",
        ToolID:    "dangerous/run",
        Args:      map[string]any{"target": "prod"},
        Timestamp: time.Now(),
    }, p.sessions.Get("agent-a"), version, handle2)

    // Push updated item into backend (DeferWithTokenOpts enqueued earlier without cascade fields)
    item := backendstore.DeferItem{
        Token:            token2,
        AgentID:          handle2.AgentID,
        ToolID:           handle2.ToolID,
        Reason:           handle2.Reason,
        Priority:         "normal",
        CreatedAt:        handle2.CreatedAt,
        Deadline:         handle2.Deadline,
        ParentDeferToken: handle2.ParentDeferToken,
        CascadeReason:    handle2.CascadeReason,
        CascadeDepth:     handle2.CascadeDepth,
        CascadePath:      handle2.CascadePath,
    }
    if err := pb.Enqueue(nil, item); err != nil {
        t.Fatalf("failed to enqueue updated item: %v", err)
    }

    // Verify backend persisted the cascade metadata for token2
    snap, err := pb.Status(nil, token2)
    if err != nil {
        t.Fatalf("backend status error: %v", err)
    }
    if snap == nil || snap.Item == nil {
        t.Fatalf("expected backend item for token2")
    }
    if snap.Item.ParentDeferToken != first.DeferToken {
        t.Fatalf("backend parent token mismatch: want %s got %s", first.DeferToken, snap.Item.ParentDeferToken)
    }
    if snap.Item.CascadeDepth != 1 {
        t.Fatalf("backend cascade depth mismatch: want 1 got %d", snap.Item.CascadeDepth)
    }

    // Resolve the inner cascade and validate resume acceptance
    if err := wf.Resolve(token2, true, "approver-2", "approved"); err != nil {
        t.Fatalf("Resolve(token2) error = %v", err)
    }
    // Validate resume approval via pipeline helper
    _, code, reason := p.validateResumeApproval(CanonicalActionRequest{
        CallID:    "call-2-resume",
        AgentID:   "agent-a",
        SessionID: "sess-1",
        ToolID:    "dangerous/run",
        Args:      map[string]any{"target": "prod"},
    }, p.sessions.Get("agent-a"), version)
    if code != "" {
        t.Fatalf("validateResumeApproval failed: code=%s reason=%s", code, reason)
    }
}
