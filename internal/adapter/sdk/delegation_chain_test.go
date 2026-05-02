package sdk

import (
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/delegate"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func newRuntimeWireServer(t *testing.T) (*Server, *delegate.Service) {
	t.Helper()
	srv := newDelegateTestServer(t)
	return srv, srv.delegate
}

func TestResolveDelegationChain_EmptyToken_ReturnsNil(t *testing.T) {
	srv, _ := newRuntimeWireServer(t)
	chain, denial := srv.resolveDelegationChain(governRequest{AgentID: "worker"})
	if chain != nil {
		t.Errorf("expected nil chain for empty token, got %+v", chain)
	}
	if denial != nil {
		t.Errorf("expected no denial for empty token, got %+v", denial)
	}
}

func TestResolveDelegationChain_InvalidToken_DeniesWithCode(t *testing.T) {
	srv, _ := newRuntimeWireServer(t)
	chain, denial := srv.resolveDelegationChain(governRequest{
		AgentID:         "worker",
		DelegationToken: "del_garbage.junk",
	})
	if chain != nil {
		t.Errorf("expected nil chain on invalid token, got %+v", chain)
	}
	if denial == nil || denial.Effect != core.EffectDeny {
		t.Fatalf("expected deny decision, got %+v", denial)
	}
	if denial.ReasonCode != reasons.DelegationTokenInvalid {
		t.Errorf("expected ReasonCode=%s, got %s", reasons.DelegationTokenInvalid, denial.ReasonCode)
	}
}

func TestResolveDelegationChain_AgentMismatch_DeniesWithCode(t *testing.T) {
	srv, svc := newRuntimeWireServer(t)
	g, err := svc.Grant(delegate.GrantRequest{FromAgent: "supervisor", ToAgent: "worker", Scope: "*", TTL: "1h"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Token issued to "worker" but call comes from "imposter".
	chain, denial := srv.resolveDelegationChain(governRequest{
		AgentID:         "imposter",
		DelegationToken: g.Token,
	})
	if chain != nil {
		t.Errorf("expected nil chain, got %+v", chain)
	}
	if denial == nil || denial.ReasonCode != reasons.DelegationTokenAgentMismatch {
		t.Fatalf("expected DelegationTokenAgentMismatch, got %+v", denial)
	}
}

func TestResolveDelegationChain_RevokedToken_Denies(t *testing.T) {
	srv, svc := newRuntimeWireServer(t)
	g, _ := svc.Grant(delegate.GrantRequest{FromAgent: "supervisor", ToAgent: "worker", Scope: "*", TTL: "1h"})
	if _, err := svc.Revoke("supervisor", "worker"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	chain, denial := srv.resolveDelegationChain(governRequest{
		AgentID:         "worker",
		DelegationToken: g.Token,
	})
	if chain != nil || denial == nil || denial.ReasonCode != reasons.DelegationTokenInvalid {
		t.Errorf("expected DelegationTokenInvalid after revoke, got chain=%+v denial=%+v", chain, denial)
	}
}

func TestResolveDelegationChain_ValidToken_PopulatesChain(t *testing.T) {
	srv, svc := newRuntimeWireServer(t)
	if _, err := svc.Grant(delegate.GrantRequest{FromAgent: "root", ToAgent: "supervisor", Scope: "*", TTL: "1h"}); err != nil {
		t.Fatalf("root grant: %v", err)
	}
	g, err := svc.Grant(delegate.GrantRequest{FromAgent: "supervisor", ToAgent: "worker", Scope: "stripe/*", TTL: "1h"})
	if err != nil {
		t.Fatalf("leaf grant: %v", err)
	}

	chain, denial := srv.resolveDelegationChain(governRequest{
		AgentID:         "worker",
		DelegationToken: g.Token,
	})
	if denial != nil {
		t.Fatalf("unexpected denial: %+v", denial)
	}
	if chain == nil {
		t.Fatal("expected non-nil chain")
	}
	if chain.Depth() != 2 {
		t.Errorf("expected chain depth=2, got %d", chain.Depth())
	}
	if chain.OriginAgent() != "supervisor" {
		t.Errorf("expected origin=supervisor, got %s", chain.OriginAgent())
	}
	if !chain.AllIdentitiesVerified() {
		t.Error("expected all identities verified for HMAC-validated chain")
	}
	if !chain.ToolInScope("stripe/refund") {
		t.Error("expected stripe/refund in scope (leaf grant scope is stripe/*)")
	}
	if chain.ToolInScope("shell/exec") {
		t.Error("expected shell/exec NOT in scope")
	}
}

func TestResolveDelegationChain_NoDelegateService_DeniesGracefully(t *testing.T) {
	srv := newDelegateTestServer(t)
	srv.delegate = nil
	chain, denial := srv.resolveDelegationChain(governRequest{
		AgentID:         "worker",
		DelegationToken: "del_anything.here",
	})
	if chain != nil || denial == nil || denial.ReasonCode != reasons.DelegationTokenInvalid {
		t.Errorf("expected denial when service unset, got chain=%+v denial=%+v", chain, denial)
	}
}

func TestSplitScopeForLink(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"*", 0},
		{"stripe/*", 1},
		{"stripe/* shell/*", 2},
		{"stripe/*, shell/*", 2},
		{"   ", 0},
	}
	for _, c := range cases {
		got := splitScopeForLink(c.in)
		if len(got) != c.want {
			t.Errorf("splitScopeForLink(%q) returned %d entries, want %d", c.in, len(got), c.want)
		}
	}
}

// Sanity check: a fresh service uses a real clock so tokens issued in the
// past survive a brief Verify call window.
func TestResolveDelegationChain_RealClockSanity(t *testing.T) {
	store := delegate.NewMemoryStore()
	svc := delegate.NewService(store, delegate.DeriveKey([]byte("k")), 5, time.Now)
	srv := newDelegateTestServer(t)
	srv.SetDelegateService(svc)

	g, _ := svc.Grant(delegate.GrantRequest{FromAgent: "a", ToAgent: "b", Scope: "*", TTL: "1h"})
	_, denial := srv.resolveDelegationChain(governRequest{AgentID: "b", DelegationToken: g.Token})
	if denial != nil {
		t.Errorf("unexpected denial on fresh real-clock token: %+v", denial)
	}
}
