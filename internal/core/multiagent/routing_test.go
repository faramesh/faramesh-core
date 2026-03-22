package multiagent

import "testing"

func TestRoutingGovernor_ReplaceManifestsAndHasManifest(t *testing.T) {
	rg := NewRoutingGovernor()
	if rg.HasManifest("o1") {
		t.Fatal("unexpected manifest")
	}
	rg.ReplaceManifests([]RoutingManifest{
		{OrchestratorID: "o1", Entries: []RoutingEntry{{AgentID: "a1"}}},
	})
	if !rg.HasManifest("o1") {
		t.Fatal("expected manifest")
	}
	allowed, _, _ := rg.CheckInvocation("o1", "a1", "sess")
	if !allowed {
		t.Fatal("expected allowed")
	}
	rg.ReplaceManifests(nil)
	if rg.HasManifest("o1") {
		t.Fatal("expected clear")
	}
}
