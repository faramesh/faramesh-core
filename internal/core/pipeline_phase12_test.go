package core

import (
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func TestRejectToolResponseWhenDisabled(t *testing.T) {
	p := &Pipeline{}
	p.SetGovernToolResponses(false)
	d, blocked := p.rejectToolResponseIfDisabled(CanonicalActionRequest{
		ActionType: ActionTypeToolResponse,
		AgentID:    "a1",
	})
	if !blocked || d.ReasonCode != reasons.RuleDeny {
		t.Fatalf("expected deny, got blocked=%v decision=%+v", blocked, d)
	}
}

func TestBudgetPoolDeny(t *testing.T) {
	p := &Pipeline{}
	p.SetBudgetPools([]agentgov.BudgetPool{
		{Name: "team", Agents: []string{"a1"}, Max: 1.0},
	})
	denied, code, _ := p.checkBudgetPool("a1", 2.0)
	if !denied || code != reasons.AggregateBudgetExceeded {
		t.Fatalf("expected pool deny, got denied=%v code=%s", denied, code)
	}
}

func TestBudgetPoolPermitAndSpend(t *testing.T) {
	p := &Pipeline{}
	p.SetBudgetPools([]agentgov.BudgetPool{
		{Name: "team", Agents: []string{"a1"}, Max: 10.0},
	})
	if denied, _, _ := p.checkBudgetPool("a1", 1.0); denied {
		t.Fatal("expected permit")
	}
	p.recordBudgetPoolSpend("a1", 1.0)
	if denied, _, _ := p.checkBudgetPool("a1", 9.5); !denied {
		t.Fatal("expected deny after spend")
	}
}
