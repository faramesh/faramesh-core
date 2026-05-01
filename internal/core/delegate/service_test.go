package delegate

import (
	"errors"
	"testing"
	"time"
)

func newTestService(t *testing.T, maxDepth int) (*Service, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)}
	svc := NewService(NewMemoryStore(), DeriveKey([]byte("test")), maxDepth, clk.Now)
	return svc, clk
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func TestService_Grant_Root(t *testing.T) {
	svc, _ := newTestService(t, 0)
	g, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", Scope: "stripe/*", TTL: "1h"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if g.ChainDepth != 1 {
		t.Errorf("expected root depth=1, got %d", g.ChainDepth)
	}
	if g.Token == "" || !g.Active {
		t.Errorf("unexpected grant: %+v", g)
	}
	if !g.ExpiresAt.After(g.IssuedAt) {
		t.Errorf("expires must be after issued")
	}
}

func TestService_Grant_RejectsEmptyOrSelfDelegation(t *testing.T) {
	svc, _ := newTestService(t, 0)
	if _, err := svc.Grant(GrantRequest{FromAgent: "", ToAgent: "b"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest on empty from, got %v", err)
	}
	if _, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "a"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest on self-delegation, got %v", err)
	}
	if _, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", TTL: "garbage"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest on bad ttl, got %v", err)
	}
}

func TestService_Grant_ChainsDepth(t *testing.T) {
	svc, _ := newTestService(t, 0)
	// Root: a → b
	if _, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", Scope: "*", TTL: "1h"}); err != nil {
		t.Fatalf("a→b: %v", err)
	}
	// Chain: b → c, parent is a→b at depth 1, so b→c is depth 2.
	g, err := svc.Grant(GrantRequest{FromAgent: "b", ToAgent: "c", Scope: "stripe/*", TTL: "1h"})
	if err != nil {
		t.Fatalf("b→c: %v", err)
	}
	if g.ChainDepth != 2 {
		t.Errorf("expected depth=2, got %d", g.ChainDepth)
	}
}

func TestService_Grant_RejectsScopeNotSubset(t *testing.T) {
	svc, _ := newTestService(t, 0)
	if _, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", Scope: "stripe/refund", TTL: "1h"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// b cannot delegate "shell/*" because parent only granted stripe/refund.
	_, err := svc.Grant(GrantRequest{FromAgent: "b", ToAgent: "c", Scope: "shell/*", TTL: "1h"})
	if !errors.Is(err, ErrScopeNotSubset) {
		t.Errorf("expected ErrScopeNotSubset, got %v", err)
	}
}

func TestService_Grant_EnforcesMaxDepth(t *testing.T) {
	svc, _ := newTestService(t, 2)
	if _, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", TTL: "1h"}); err != nil {
		t.Fatalf("a→b: %v", err)
	}
	if _, err := svc.Grant(GrantRequest{FromAgent: "b", ToAgent: "c", TTL: "1h"}); err != nil {
		t.Fatalf("b→c: %v", err)
	}
	// c→d would be depth 3, exceeds max=2.
	_, err := svc.Grant(GrantRequest{FromAgent: "c", ToAgent: "d", TTL: "1h"})
	if !errors.Is(err, ErrChainTooDeep) {
		t.Errorf("expected ErrChainTooDeep, got %v", err)
	}
}

func TestService_Verify_LifecycleStates(t *testing.T) {
	svc, clk := newTestService(t, 0)
	g, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", Scope: "stripe/*", TTL: "1h"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Active.
	if r := svc.Verify(g.Token); !r.Valid {
		t.Errorf("expected valid, got %+v", r)
	}

	// Tampered token rejected before store hit.
	if r := svc.Verify(g.Token + "junk"); r.Valid || r.Reason == "" {
		t.Errorf("expected invalid+reason for tampered, got %+v", r)
	}

	// Revoked.
	if _, err := svc.Revoke("a", "b"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r := svc.Verify(g.Token); r.Valid || r.Reason != "revoked" {
		t.Errorf("expected revoked, got %+v", r)
	}

	// Expired (after re-granting on a fresh service).
	svc2, clk2 := newTestService(t, 0)
	g2, _ := svc2.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", TTL: "1h"})
	clk2.Advance(2 * time.Hour)
	if r := svc2.Verify(g2.Token); r.Valid || r.Reason != "expired" {
		t.Errorf("expected expired, got %+v", r)
	}

	_ = clk
}

func TestService_Chain_ReconstructsRootToLeaf(t *testing.T) {
	svc, _ := newTestService(t, 0)
	mustGrant(t, svc, "a", "b", "*")
	mustGrant(t, svc, "b", "c", "stripe/*")
	mustGrant(t, svc, "c", "d", "stripe/refund")

	chain := svc.Chain("d")
	if len(chain) != 3 {
		t.Fatalf("expected 3-link chain, got %d (%+v)", len(chain), chain)
	}
	if chain[0].FromAgent != "a" || chain[0].ToAgent != "b" {
		t.Errorf("expected root a→b first, got %+v", chain[0])
	}
	if chain[2].FromAgent != "c" || chain[2].ToAgent != "d" {
		t.Errorf("expected leaf c→d last, got %+v", chain[2])
	}
}

func TestService_Chain_StopsOnCycle(t *testing.T) {
	// Construct a cycle by manipulating the store directly: a→b active and
	// b→a active. Walk from a should not loop forever.
	store := NewMemoryStore()
	now := time.Now()
	_ = store.Insert(Grant{Token: "t1", FromAgent: "a", ToAgent: "b", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: true, ChainDepth: 1})
	_ = store.Insert(Grant{Token: "t2", FromAgent: "b", ToAgent: "a", IssuedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour), Active: true, ChainDepth: 1})
	svc := NewService(store, DeriveKey([]byte("k")), 0, func() time.Time { return now })
	chain := svc.Chain("a")
	if len(chain) > 2 {
		t.Errorf("expected cycle to terminate within 2 hops, got %d", len(chain))
	}
}

func TestService_List_IncludesBothSides(t *testing.T) {
	svc, _ := newTestService(t, 0)
	mustGrant(t, svc, "a", "b", "*")
	mustGrant(t, svc, "x", "a", "*")
	got := svc.List("a")
	if len(got) != 2 {
		t.Errorf("expected 2 grants for a, got %d", len(got))
	}
}

func TestScopeIsSubset(t *testing.T) {
	cases := []struct {
		child, parent string
		want          bool
	}{
		{"stripe/refund", "stripe/*", true},
		{"stripe/*", "stripe/*", true},
		{"shell/exec", "stripe/*", false},
		{"anything", "*", true},
		{"stripe/refund stripe/charge", "stripe/*", true},
		{"stripe/refund shell/exec", "stripe/*", false},
		{"stripe/*", "stripe/refund", false},
	}
	for _, c := range cases {
		if got := scopeIsSubset(c.child, c.parent); got != c.want {
			t.Errorf("scopeIsSubset(%q, %q) = %v, want %v", c.child, c.parent, got, c.want)
		}
	}
}

func mustGrant(t *testing.T, svc *Service, from, to, scope string) Grant {
	t.Helper()
	g, err := svc.Grant(GrantRequest{FromAgent: from, ToAgent: to, Scope: scope, TTL: "1h"})
	if err != nil {
		t.Fatalf("grant %s→%s: %v", from, to, err)
	}
	return g
}
