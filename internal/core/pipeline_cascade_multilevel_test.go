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

func TestPipelineCascade_MultilevelAllowsAndDeniesByDepth(t *testing.T) {
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

    // A -> B -> C chain
    a := p.Evaluate(CanonicalActionRequest{CallID: "a", AgentID: "agent-a", SessionID: "s", ToolID: "dangerous/run", Args: map[string]any{"x": 1}, Timestamp: time.Now()})
    if a.Effect != EffectDefer { t.Fatalf("expected defer for A") }

    // create B cascading from A
    bTok := deterministicDeferToken("b", "dangerous/run")
    hB, _ := p.defers.DeferWithTokenOpts(bTok, "agent-a", "dangerous/run", "cascade", deferwork.DeferOptions{})
    hB.ParentDeferToken = a.DeferToken
    hB.CascadeDepth = 1
    hB.CascadePath = []string{a.DeferToken}
    p.storeDeferContext(bTok, CanonicalActionRequest{CallID: "b" , AgentID: "agent-a", SessionID: "s", ToolID: "dangerous/run", Args: map[string]any{"x":2}, Timestamp: time.Now()}, p.sessions.Get("agent-a"), version, hB)

    // create C cascading from B with depth within limit (3 default)
    cTok := deterministicDeferToken("c", "dangerous/run")
    hC, _ := p.defers.DeferWithTokenOpts(cTok, "agent-a", "dangerous/run", "cascade", deferwork.DeferOptions{})
    hC.ParentDeferToken = bTok
    hC.CascadeDepth = 2
    hC.CascadePath = []string{a.DeferToken, bTok}
    p.storeDeferContext(cTok, CanonicalActionRequest{CallID: "c" , AgentID: "agent-a", SessionID: "s", ToolID: "dangerous/run", Args: map[string]any{"x":3}, Timestamp: time.Now()}, p.sessions.Get("agent-a"), version, hC)

    // Resolve C and expect resume to be permitted (depth 2 <= default max 3)
    if err := wf.Resolve(cTok, true, "approver", "approved"); err != nil { t.Fatalf("resolve c: %v", err) }
    _, code, _ := p.validateResumeApproval(CanonicalActionRequest{CallID:"c-resume", AgentID:"agent-a", SessionID:"s", ToolID:"dangerous/run", Args: map[string]any{"x":3}}, p.sessions.Get("agent-a"), version)
    if code != "" { t.Fatalf("expected resume permitted for depth 2, got code=%s", code) }

    // Now artificially increase depth to exceed default max (set to 4)
    ctxB := wf.Context(bTok)
    if ctxB == nil { t.Fatalf("expected context for B") }
    ctxB.CascadeDepth = 5
    // Resolve B and expect resume to be rejected with CascadeDepthLimit
    if err := wf.Resolve(bTok, true, "approver", "approved"); err != nil { t.Fatalf("resolve b: %v", err) }
    _, code2, _ := p.validateResumeApproval(CanonicalActionRequest{CallID:"b-resume", AgentID:"agent-a", SessionID:"s", ToolID:"dangerous/run", Args: map[string]any{"x":2}}, p.sessions.Get("agent-a"), version)
    if code2 != reasons.CascadeDepthLimit { t.Fatalf("expected cascade depth limit, got %s", code2) }
}
