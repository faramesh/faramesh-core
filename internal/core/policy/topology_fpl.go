package policy

import (
	"fmt"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

// PreviewOrchestratorManifestFromFPLStatements materializes orchestrator_manifest from FPL topology
// lines alone (empty YAML base). Used by CLI JSON preview.
func PreviewOrchestratorManifestFromFPLStatements(stmts []fpl.TopoStatement) (*OrchestratorManifest, error) {
	d := &Doc{}
	if err := mergeOrchestratorManifestFromFPL(d, stmts); err != nil {
		return nil, err
	}
	return d.OrchestratorManifest, nil
}

// mergeOrchestratorManifestFromFPL folds topology statements from FPL into doc.OrchestratorManifest.
// YAML entries are the base; each FPL manifest allow replaces or appends by target agent_id.
// FPL manifest orchestrator … undeclared … sets orchestrator_id and undeclared policy when present.
func mergeOrchestratorManifestFromFPL(doc *Doc, stmts []fpl.TopoStatement) error {
	if doc == nil || len(stmts) == 0 {
		return nil
	}

	var orchID string
	var fplUndeclared string
	orchDeclSeen := false
	allows := make(map[string]AgentInvocation)
	var allowOrder []string

	for _, st := range stmts {
		switch st.Kind {
		case fpl.TopoOrchestrator:
			if orchDeclSeen && st.OrchID != orchID {
				return fmt.Errorf("fpl topology: multiple orchestrator declarations (%q vs %q)", orchID, st.OrchID)
			}
			orchDeclSeen = true
			orchID = st.OrchID
			if st.UndeclaredPolicy != "" {
				fplUndeclared = st.UndeclaredPolicy
			}
		case fpl.TopoAllow:
			o := st.AllowOrchID
			if o == "" {
				return fmt.Errorf("fpl topology: manifest grant missing orchestrator id")
			}
			if orchID == "" {
				orchID = o
			} else if o != orchID {
				return fmt.Errorf("fpl topology: manifest allow orchestrator %q does not match %q", o, orchID)
			}
			tgt := st.TargetAgentID
			if tgt == "" {
				return fmt.Errorf("fpl topology: manifest grant missing target agent")
			}
			if _, ok := allows[tgt]; !ok {
				allowOrder = append(allowOrder, tgt)
			}
			allows[tgt] = AgentInvocation{
				AgentID:                  tgt,
				MaxInvocationsPerSession: st.MaxPerSession,
				RequiresPriorApproval:    st.RequiresApproval,
			}
		}
	}

	if orchID == "" && len(allows) == 0 {
		return nil
	}
	if orchID == "" {
		return fmt.Errorf("fpl topology: manifest allow lines without orchestrator id")
	}

	yamlOrch := ""
	if doc.OrchestratorManifest != nil {
		yamlOrch = strings.TrimSpace(doc.OrchestratorManifest.AgentID)
	}
	if yamlOrch != "" && yamlOrch != orchID {
		return fmt.Errorf("fpl topology: orchestrator_id %q conflicts with yaml orchestrator_manifest.agent_id %q",
			orchID, yamlOrch)
	}

	undeclared := "deny"
	if doc.OrchestratorManifest != nil && doc.OrchestratorManifest.UndeclaredInvocationPolicy != "" {
		undeclared = strings.ToLower(strings.TrimSpace(doc.OrchestratorManifest.UndeclaredInvocationPolicy))
	}
	if orchDeclSeen && fplUndeclared != "" {
		undeclared = fplUndeclared
	}

	byID := make(map[string]AgentInvocation)
	var order []string
	add := func(inv AgentInvocation) {
		id := inv.AgentID
		if _, ok := byID[id]; !ok {
			order = append(order, id)
		}
		byID[id] = inv
	}

	if doc.OrchestratorManifest != nil {
		for _, inv := range doc.OrchestratorManifest.PermittedInvocations {
			add(inv)
		}
	}
	for _, id := range allowOrder {
		add(allows[id])
	}

	merged := make([]AgentInvocation, 0, len(order))
	for _, id := range order {
		merged = append(merged, byID[id])
	}

	if doc.OrchestratorManifest == nil {
		doc.OrchestratorManifest = &OrchestratorManifest{}
	}
	doc.OrchestratorManifest.AgentID = orchID
	doc.OrchestratorManifest.UndeclaredInvocationPolicy = undeclared
	doc.OrchestratorManifest.PermittedInvocations = merged
	return nil
}
