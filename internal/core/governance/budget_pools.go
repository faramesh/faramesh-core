package governance

import (
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

// BudgetPoolsFromDocument collects deduplicated budget pools declared on agents.
func BudgetPoolsFromDocument(doc *ast.Document) []agentgov.BudgetPool {
	if doc == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []agentgov.BudgetPool
	for _, ag := range doc.Agents {
		if ag == nil {
			continue
		}
		for _, p := range ag.BudgetPools {
			name := strings.TrimSpace(p.Name)
			if name == "" || p.Max <= 0 {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, agentgov.BudgetPool{
				Name:   name,
				Agents: append([]string(nil), p.Agents...),
				Max:    p.Max,
			})
		}
	}
	return out
}
