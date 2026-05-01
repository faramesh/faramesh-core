package delegate

import (
	"testing"
	"time"
)

func TestMemoryStore_InsertAndGet(t *testing.T) {
	s := NewMemoryStore()
	g := Grant{Token: "del_x.y", FromAgent: "a", ToAgent: "b", Active: true, IssuedAt: time.Now()}
	if err := s.Insert(g); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, ok := s.GetByToken("del_x.y")
	if !ok {
		t.Fatal("expected token to be retrievable")
	}
	if got.FromAgent != "a" || got.ToAgent != "b" {
		t.Errorf("unexpected grant: %+v", got)
	}
}

func TestMemoryStore_Insert_RejectsEmptyTokenAndDuplicates(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Insert(Grant{Token: ""}); err == nil {
		t.Fatal("expected error on empty token")
	}
	g := Grant{Token: "del_dup", FromAgent: "a", ToAgent: "b", Active: true}
	if err := s.Insert(g); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := s.Insert(g); err != ErrDuplicateToken {
		t.Fatalf("expected ErrDuplicateToken, got %v", err)
	}
}

func TestMemoryStore_ListByAgent_NewestFirst(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	_ = s.Insert(Grant{Token: "t1", FromAgent: "a", ToAgent: "b", IssuedAt: now.Add(-2 * time.Hour), Active: true})
	_ = s.Insert(Grant{Token: "t2", FromAgent: "a", ToAgent: "c", IssuedAt: now, Active: true})
	_ = s.Insert(Grant{Token: "t3", FromAgent: "x", ToAgent: "y", IssuedAt: now.Add(-1 * time.Hour), Active: true})

	got := s.ListByAgent("a")
	if len(got) != 2 {
		t.Fatalf("expected 2 grants for a, got %d", len(got))
	}
	if got[0].Token != "t2" || got[1].Token != "t1" {
		t.Errorf("expected newest-first ordering, got %v %v", got[0].Token, got[1].Token)
	}
}

func TestMemoryStore_ListInbound_OnlyActive(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	_ = s.Insert(Grant{Token: "t1", FromAgent: "a", ToAgent: "b", IssuedAt: now, Active: true})
	_ = s.Insert(Grant{Token: "t2", FromAgent: "x", ToAgent: "b", IssuedAt: now.Add(-time.Hour), Active: false})
	got := s.ListInbound("b")
	if len(got) != 1 || got[0].Token != "t1" {
		t.Errorf("expected only active inbound t1, got %+v", got)
	}
}

func TestMemoryStore_Revoke(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	_ = s.Insert(Grant{Token: "t1", FromAgent: "a", ToAgent: "b", IssuedAt: now, Active: true})
	_ = s.Insert(Grant{Token: "t2", FromAgent: "a", ToAgent: "b", IssuedAt: now, Active: true})
	_ = s.Insert(Grant{Token: "t3", FromAgent: "a", ToAgent: "c", IssuedAt: now, Active: true})

	n, err := s.Revoke("a", "b")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 revoked, got %d", n)
	}
	// Idempotent: subsequent revoke is a no-op.
	n2, _ := s.Revoke("a", "b")
	if n2 != 0 {
		t.Errorf("expected 0 on second revoke, got %d", n2)
	}
	// Untouched grants remain active.
	g, _ := s.GetByToken("t3")
	if !g.Active {
		t.Error("expected t3 to remain active")
	}
}

func TestGrant_IsValidAt(t *testing.T) {
	now := time.Now()
	g := Grant{Active: true, ExpiresAt: now.Add(time.Hour)}
	if !g.IsValidAt(now) {
		t.Error("expected valid")
	}
	g.Active = false
	if g.IsValidAt(now) {
		t.Error("inactive should be invalid")
	}
	g.Active = true
	g.ExpiresAt = now.Add(-time.Second)
	if g.IsValidAt(now) {
		t.Error("expired should be invalid")
	}
	var nilG *Grant
	if nilG.IsValidAt(now) {
		t.Error("nil grant must be invalid")
	}
}
