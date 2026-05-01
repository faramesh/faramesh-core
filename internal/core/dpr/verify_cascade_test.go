package dpr

import "testing"

func TestVerifyCascadeChainAcceptsValidChain(t *testing.T) {
	a := &Record{RecordID: "r-a", DeferToken: "tok-a", CascadeDepth: 0, CascadePath: nil}
	b := &Record{RecordID: "r-b", DeferToken: "tok-b", ParentDeferToken: "tok-a", CascadeDepth: 1, CascadePath: []string{"tok-a"}}
	c := &Record{RecordID: "r-c", DeferToken: "tok-c", ParentDeferToken: "tok-b", CascadeDepth: 2, CascadePath: []string{"tok-a", "tok-b"}}
	if err := VerifyCascadeChain([]*Record{a, b, c}); err != nil {
		t.Fatalf("VerifyCascadeChain returned error: %v", err)
	}
}

func TestVerifyCascadeChainRejectsMissingParent(t *testing.T) {
	b := &Record{RecordID: "r-b", DeferToken: "tok-b", ParentDeferToken: "tok-missing", CascadeDepth: 1, CascadePath: []string{"tok-missing"}}
	if err := VerifyCascadeChain([]*Record{b}); err == nil {
		t.Fatal("expected missing parent error")
	}
}

func TestVerifyCascadeChainRejectsCycle(t *testing.T) {
	a := &Record{RecordID: "r-a", DeferToken: "tok-a", ParentDeferToken: "tok-c", CascadeDepth: 2, CascadePath: []string{"tok-b", "tok-c"}}
	b := &Record{RecordID: "r-b", DeferToken: "tok-b", ParentDeferToken: "tok-a", CascadeDepth: 1, CascadePath: []string{"tok-a"}}
	c := &Record{RecordID: "r-c", DeferToken: "tok-c", ParentDeferToken: "tok-b", CascadeDepth: 2, CascadePath: []string{"tok-a", "tok-b"}}
	if err := VerifyCascadeChain([]*Record{a, b, c}); err == nil {
		t.Fatal("expected cycle error")
	}
}
