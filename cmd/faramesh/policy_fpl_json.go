package main

import "github.com/faramesh/faramesh-core/internal/core/policy"

func fplTopologyJSON(m *policy.OrchestratorManifest) any {
	if m == nil {
		return nil
	}
	type inv struct {
		AgentID                  string `json:"agent_id"`
		MaxInvocationsPerSession int    `json:"max_invocations_per_session"`
		RequiresPriorApproval    bool   `json:"requires_prior_approval"`
	}
	out := struct {
		AgentID                    string `json:"agent_id"`
		UndeclaredInvocationPolicy string `json:"undeclared_invocation_policy"`
		PermittedInvocations       []inv  `json:"permitted_invocations,omitempty"`
	}{
		AgentID:                    m.AgentID,
		UndeclaredInvocationPolicy: m.UndeclaredInvocationPolicy,
	}
	for _, p := range m.PermittedInvocations {
		out.PermittedInvocations = append(out.PermittedInvocations, inv{
			AgentID:                  p.AgentID,
			MaxInvocationsPerSession: p.MaxInvocationsPerSession,
			RequiresPriorApproval:    p.RequiresPriorApproval,
		})
	}
	return out
}
