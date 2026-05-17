package core

import (
	"context"
	"strings"
	"time"

	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
)

func (p *Pipeline) estimatedToolCostUSD(req CanonicalActionRequest, fallback float64) float64 {
	if p == nil || p.costEstimator == nil || fallback > 0 {
		return fallback
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := p.costEstimator.CostEstimate(ctx, &providerv1.CostRequest{
		ActionType: string(NormalizeActionType(req.ActionType)),
		Attributes: map[string]string{
			"agent_id": req.AgentID,
			"tool_id":  req.ToolID,
		},
	})
	if err != nil || resp == nil || resp.Amount <= 0 {
		return fallback
	}
	if cur := strings.TrimSpace(resp.Currency); cur != "" && !strings.EqualFold(cur, "USD") {
		return fallback
	}
	return resp.Amount
}
