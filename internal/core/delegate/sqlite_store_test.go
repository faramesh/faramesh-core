package delegate

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) (*SQLiteStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "delegations.db")
	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func TestSQLiteStore_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested", "subdir", "delegations.db")
	store, err := OpenSQLiteStore(nested)
	if err != nil {
		t.Fatalf("open with nested path: %v", err)
	}
	defer store.Close()
}

func TestSQLiteStore_RejectsEmptyPath(t *testing.T) {
	if _, err := OpenSQLiteStore(""); err == nil {
		t.Error("expected error on empty path")
	}
}

func TestSQLiteStore_InsertAndGet(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	g := Grant{
		Token: "del_test.1", FromAgent: "a", ToAgent: "b", Scope: "stripe/*",
		Ceiling: "amount<=500", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		ChainDepth: 1, Active: true,
	}
	if err := store.Insert(g); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, ok := store.GetByToken("del_test.1")
	if !ok {
		t.Fatal("expected grant to be retrievable")
	}
	if got.FromAgent != "a" || got.ToAgent != "b" || got.Scope != "stripe/*" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if !got.IssuedAt.Equal(now) || !got.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("time roundtrip mismatch: %+v", got)
	}
	if got.Ceiling != "amount<=500" || got.ChainDepth != 1 || !got.Active {
		t.Errorf("scalar roundtrip mismatch: %+v", got)
	}
}

func TestSQLiteStore_RejectsDuplicateToken(t *testing.T) {
	store, _ := openTestStore(t)
	g := Grant{Token: "del_dup", FromAgent: "a", ToAgent: "b", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Active: true}
	if err := store.Insert(g); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := store.Insert(g)
	if !errors.Is(err, ErrDuplicateToken) {
		t.Errorf("expected ErrDuplicateToken, got %v", err)
	}
}

func TestSQLiteStore_ListByAgent_NewestFirst(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	mustInsert(t, store, Grant{Token: "t1", FromAgent: "a", ToAgent: "b", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour), Active: true})
	mustInsert(t, store, Grant{Token: "t2", FromAgent: "a", ToAgent: "c", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: true})
	mustInsert(t, store, Grant{Token: "t3", FromAgent: "x", ToAgent: "y", IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Active: true})

	got := store.ListByAgent("a")
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].Token != "t2" || got[1].Token != "t1" {
		t.Errorf("expected newest-first, got %v %v", got[0].Token, got[1].Token)
	}
}

func TestSQLiteStore_ListInbound_OnlyActive(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	mustInsert(t, store, Grant{Token: "t1", FromAgent: "a", ToAgent: "b", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: true})
	mustInsert(t, store, Grant{Token: "t2", FromAgent: "x", ToAgent: "b", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: false})
	got := store.ListInbound("b")
	if len(got) != 1 || got[0].Token != "t1" {
		t.Errorf("expected only active inbound, got %+v", got)
	}
}

func TestSQLiteStore_Revoke(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	mustInsert(t, store, Grant{Token: "t1", FromAgent: "a", ToAgent: "b", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: true})
	mustInsert(t, store, Grant{Token: "t2", FromAgent: "a", ToAgent: "b", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: true})
	mustInsert(t, store, Grant{Token: "t3", FromAgent: "a", ToAgent: "c", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Active: true})

	n, err := store.Revoke("a", "b")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 revoked, got %d", n)
	}
	// Idempotent.
	n2, _ := store.Revoke("a", "b")
	if n2 != 0 {
		t.Errorf("expected 0 on second revoke, got %d", n2)
	}
	// Untouched grant stays active.
	g, ok := store.GetByToken("t3")
	if !ok || !g.Active {
		t.Error("expected t3 to remain active")
	}
}

// TestSQLiteStore_PersistsAcrossReopen is the audit-trail acceptance test:
// grants survive process restart.
func TestSQLiteStore_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "delegations.db")
	now := time.Now().UTC().Truncate(time.Second)

	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	g := Grant{Token: "del_persist", FromAgent: "a", ToAgent: "b", Scope: "*", IssuedAt: now, ExpiresAt: now.Add(time.Hour), ChainDepth: 1, Active: true}
	if err := store.Insert(g); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	got, ok := reopened.GetByToken("del_persist")
	if !ok {
		t.Fatal("grant did not survive reopen")
	}
	if got.FromAgent != "a" || got.ToAgent != "b" {
		t.Errorf("post-reopen grant mismatch: %+v", got)
	}
	if !got.IssuedAt.Equal(now) {
		t.Errorf("post-reopen time mismatch: %v != %v", got.IssuedAt, now)
	}
}

// TestSQLiteStore_BackedService verifies the Service contract holds when
// backed by SQLite, exercising the same flows as the in-memory tests.
func TestSQLiteStore_BackedService(t *testing.T) {
	store, _ := openTestStore(t)
	clk := func() time.Time { return time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC) }
	svc := NewService(store, DeriveKey([]byte("k")), 5, clk)

	root, err := svc.Grant(GrantRequest{FromAgent: "a", ToAgent: "b", Scope: "*", TTL: "1h"})
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if r := svc.Verify(root.Token); !r.Valid {
		t.Errorf("expected valid, got %+v", r)
	}

	chained, err := svc.Grant(GrantRequest{FromAgent: "b", ToAgent: "c", Scope: "stripe/*", TTL: "1h"})
	if err != nil {
		t.Fatalf("chained: %v", err)
	}
	if chained.ChainDepth != 2 {
		t.Errorf("expected depth=2, got %d", chained.ChainDepth)
	}

	// Scope subset enforcement still works through SQLite.
	if _, err := svc.Grant(GrantRequest{FromAgent: "c", ToAgent: "d", Scope: "shell/*", TTL: "1h"}); !errors.Is(err, ErrScopeNotSubset) {
		t.Errorf("expected ErrScopeNotSubset, got %v", err)
	}

	// Chain reconstruction from SQLite-backed store.
	chain := svc.Chain("c")
	if len(chain) != 2 {
		t.Fatalf("expected 2-link chain, got %d", len(chain))
	}
	if chain[0].FromAgent != "a" || chain[1].ToAgent != "c" {
		t.Errorf("unexpected chain ordering: %+v", chain)
	}

	// Revoke and re-verify.
	if _, err := svc.Revoke("a", "b"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r := svc.Verify(root.Token); r.Valid {
		t.Errorf("expected invalid after revoke, got %+v", r)
	}
}

func mustInsert(t *testing.T, s Store, g Grant) {
	t.Helper()
	if err := s.Insert(g); err != nil {
		t.Fatalf("insert %s: %v", g.Token, err)
	}
}
