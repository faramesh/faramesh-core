package core

import (
    "testing"
    "time"

    backendstore "github.com/faramesh/faramesh-core/internal/core/defer/backends"
    deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
    "github.com/faramesh/faramesh-core/internal/core/policy"
    "github.com/faramesh/faramesh-core/internal/core/reasons"
    "github.com/faramesh/faramesh-core/internal/core/session"
)

func TestPipelineCascade_DetectsCycleOnResume(t *testing.T) {
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

    // Create A and B as pending handles then link them to form a cycle
    aTok := deterministicDeferToken("a", "dangerous/run")
    hA, _ := p.defers.DeferWithTokenOpts(aTok, "agent-a", "dangerous/run", "cascade", deferwork.DeferOptions{})

    bTok := deterministicDeferToken("b", "dangerous/run")
    hB, _ := p.defers.DeferWithTokenOpts(bTok, "agent-a", "dangerous/run", "cascade", deferwork.DeferOptions{})

    // link A -> B and B -> A (cycle)
    hA.ParentDeferToken = bTok
    hA.CascadeDepth = 1
    p.storeDeferContext(aTok, CanonicalActionRequest{CallID: "a" , AgentID: "agent-a", SessionID: "s", ToolID: "dangerous/run", Args: map[string]any{"x":1}, Timestamp: time.Now()}, p.sessions.Get("agent-a"), version, hA)

    hB.ParentDeferToken = aTok
    hB.CascadeDepth = 1
    p.storeDeferContext(bTok, CanonicalActionRequest{CallID: "b" , AgentID: "agent-a", SessionID: "s", ToolID: "dangerous/run", Args: map[string]any{"x":2}, Timestamp: time.Now()}, p.sessions.Get("agent-a"), version, hB)

    // Resolve B and expect resume of B to be rejected due to cycle prevention
    if err := wf.Resolve(bTok, true, "approver", "approved"); err != nil { t.Fatalf("resolve b: %v", err) }
    _, code, _ := p.validateResumeApproval(CanonicalActionRequest{CallID:"b-resume", AgentID:"agent-a", SessionID:"s", ToolID:"dangerous/run", Args: map[string]any{"x":2}}, p.sessions.Get("agent-a"), version)
    if code != reasons.CyclePrevention { t.Fatalf("expected cycle prevention, got %s", code) }
}
