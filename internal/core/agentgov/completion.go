package agentgov

import (
	"fmt"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

// CompletionSatisfied checks compiled completion_gate requires against session DPR history.
func (g *CompletionGate) CompletionSatisfied(records []*dpr.Record) bool {
	if g == nil || len(g.Requires) == 0 {
		return true
	}
	for _, req := range g.Requires {
		if !predicateSatisfied(strings.TrimSpace(req), records) {
			return false
		}
	}
	return true
}

func predicateSatisfied(req string, records []*dpr.Record) bool {
	req = strings.ToLower(req)
	switch {
	case req == "all_tools_permitted" || req == "no_pending_defers":
		for _, rec := range records {
			if rec == nil {
				continue
			}
			if strings.EqualFold(rec.Effect, "DEFER") {
				return false
			}
		}
		return len(records) > 0
	case strings.HasPrefix(req, "effect:"):
		want := strings.TrimPrefix(req, "effect:")
		for _, rec := range records {
			if rec != nil && strings.EqualFold(rec.Effect, want) {
				return true
			}
		}
		return false
	case strings.HasPrefix(req, "min_records:"):
		var n int
		_, _ = fmt.Sscanf(req, "min_records:%d", &n)
		return len(records) >= n
	default:
		// tool_id match — at least one permit for tool
		for _, rec := range records {
			if rec != nil && strings.EqualFold(rec.ToolID, req) && strings.EqualFold(rec.Effect, "PERMIT") {
				return true
			}
		}
		return false
	}
}
