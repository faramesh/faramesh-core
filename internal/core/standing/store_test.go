package standing

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOpenRegistryStorePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "grants.db")
	r1, err := OpenRegistryStore(p1)
	if err != nil {
		t.Fatal(err)
	}
	g, err := r1.Add(Input{
		AgentID:     "agent-a",
		ToolPattern: "tools/*",
		RuleID:      "r1",
		TTL:         time.Hour,
		MaxUses:     2,
		IssuedBy:    "op",
	})
	if err != nil {
		t.Fatal(err)
	}
	id := g.ID
	if err := r1.Close(); err != nil {
		t.Fatal(err)
	}

	r2, err := OpenRegistryStore(p1)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	list := r2.List()
	if len(list) != 1 {
		t.Fatalf("list len = %d want 1", len(list))
	}
	if list[0].ID != id || list[0].Uses != 0 {
		t.Fatalf("loaded grant: %+v", list[0])
	}
	now := time.Now().UTC()
	if r2.TryConsume("agent-a", "", "tools/x", "", "r1", now) == nil {
		t.Fatal("expected consume after reopen")
	}
	if err := r2.Close(); err != nil {
		t.Fatal(err)
	}

	r3, err := OpenRegistryStore(p1)
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Close()
	list = r3.List()
	if len(list) != 1 || list[0].Uses != 1 {
		t.Fatalf("after consume persist: %+v", list)
	}
}
