package governstate

import (
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

func TestTrackerRateLimitWindow(t *testing.T) {
	tr := New()
	rules := []agentgov.RateLimit{{Tool: "tool/x", Limit: 2, Window: "minute"}}
	now := time.Now()
	if exceeded, _ := tr.CheckRate("a", "tool/x", rules, now); exceeded {
		t.Fatal("expected first check allowed")
	}
	tr.RecordRate("a", rules[0], now)
	tr.RecordRate("a", rules[0], now)
	if exceeded, _ := tr.CheckRate("a", "tool/x", rules, now); !exceeded {
		t.Fatal("expected third check denied")
	}
}

func TestTrackerApplyControlBudget(t *testing.T) {
	tr := New()
	tr.Apply(&dpr.ControlFrame{
		FrameKind: dpr.FrameKindBudgetUpdate,
		AgentID:   "a",
		Scope:     "session",
		SpentUSD:  3.5,
	})
	if got := tr.BudgetSpent("a", "session"); got != 3.5 {
		t.Fatalf("spent=%v", got)
	}
}
