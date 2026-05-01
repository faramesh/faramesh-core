package core

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

const (
	OutputOutcomePass     = "PASS"
	OutputOutcomeRedacted = "REDACTED"
	OutputOutcomeDenied   = "DENIED"
	OutputOutcomeDeferred = "DEFERRED"

	defaultOutputType = "aggregate"
	maxOutputSources  = 64
)

var allowedOutputScans = map[string]struct{}{
	"entity_extraction": {},
}

type GovernOutputRequest struct {
	AgentID        string
	SessionID      string
	OutputType     string
	Output         string
	SourceAgentIDs []string
}

type GovernOutputResult struct {
	Outcome         string
	SanitizedOutput string
	ReasonCode      string
	Reason          string
	DeferToken      string
}

type compiledOutputRule struct {
	outputType string
	rule       outputRuleView
	program    *vm.Program
}

type outputRuleView struct {
	ID        string
	Scan      map[string]bool
	Condition string
	OnMatch   string
	Reason    string
}

type outputRuleEvalEnv struct {
	Output      string                        `expr:"output"`
	OutputLen   int                           `expr:"output_len"`
	OutputType  string                        `expr:"output_type"`
	SessionID   string                        `expr:"session_id"`
	SourceCount int                           `expr:"source_count"`
	EntityCount int                           `expr:"entity_count"`
	EntityTypes []string                      `expr:"entity_types"`
	Entities    []multiagent.EntityExtraction `expr:"entities"`
}

func (p *Pipeline) GovernOutput(req GovernOutputRequest) GovernOutputResult {
	outType := normalizeOutputType(req.OutputType)

	sources := make([]multiagent.AggregationSource, 0, len(req.SourceAgentIDs))
	seenSources := map[string]struct{}{}
	for _, agentID := range req.SourceAgentIDs {
		if len(sources) >= maxOutputSources {
			break
		}
		aid := strings.TrimSpace(agentID)
		if aid == "" {
			continue
		}
		if _, exists := seenSources[aid]; exists {
			continue
		}
		seenSources[aid] = struct{}{}
		sources = append(sources, multiagent.AggregationSource{AgentID: aid, Output: req.Output})
	}

	aggregate := multiagent.AggregateResult{
		SessionID:   strings.TrimSpace(req.SessionID),
		Sources:     sources,
		Synthesized: req.Output,
	}
	aggregate.Hash = multiagent.HashAggregate(aggregate)

	governor := p.aggGovernor
	if governor == nil {
		governor = multiagent.NewAggregationGovernor(multiagent.AggregatePolicy{})
	}
	if governor.SemanticDriftObserver() == nil {
		governor.SetSemanticDriftObserver(observe.Default)
	}

	governedOutput, entities, err := governor.GovernOutput(aggregate)
	if err != nil {
		return GovernOutputResult{
			Outcome:    OutputOutcomeDenied,
			ReasonCode: reasons.OutputSchemaDeny,
			Reason:     err.Error(),
		}
	}

	result := GovernOutputResult{
		Outcome:         OutputOutcomePass,
		SanitizedOutput: governedOutput,
	}
	if governedOutput != req.Output {
		result.Outcome = OutputOutcomeRedacted
	}

	compiled, compileErr := p.compileOutputRules(outType)
	if compileErr != nil {
		return GovernOutputResult{
			Outcome:    OutputOutcomeDenied,
			ReasonCode: reasons.OutputSchemaDeny,
			Reason:     compileErr.Error(),
		}
	}

	for _, cr := range compiled {
		if !cr.rule.Scan["entity_extraction"] {
			continue
		}

		env := outputRuleEvalEnv{
			Output:      governedOutput,
			OutputLen:   len(governedOutput),
			OutputType:  outType,
			SessionID:   aggregate.SessionID,
			SourceCount: len(aggregate.Sources),
			EntityCount: len(entities),
			EntityTypes: outputEntityTypes(entities),
			Entities:    entities,
		}

		matched, evalErr := p.evalOutputRule(cr, env)
		if evalErr != nil {
			return GovernOutputResult{
				Outcome:    OutputOutcomeDenied,
				ReasonCode: reasons.OutputSchemaDeny,
				Reason:     evalErr.Error(),
			}
		}
		if !matched {
			continue
		}

		onMatch := strings.ToLower(strings.TrimSpace(cr.rule.OnMatch))
		switch onMatch {
		case "defer":
			reason := strings.TrimSpace(cr.rule.Reason)
			if reason == "" {
				reason = fmt.Sprintf("output policy %q requires human approval", cr.rule.ID)
			}
			token := deterministicOutputDeferToken(strings.TrimSpace(req.AgentID), aggregate.SessionID, outType, aggregate.Hash, cr.rule.ID)
			if p.defers != nil {
				if _, err := p.defers.DeferWithToken(token, req.AgentID, "multiagent/output", reason); err != nil {
					// Keep deterministic token semantics.
				}
			}
			if strings.TrimSpace(token) == "" {
				token = deterministicOutputDeferToken("unknown", aggregate.SessionID, outType, governedOutput, cr.rule.ID)
			}
			return GovernOutputResult{
				Outcome:         OutputOutcomeDeferred,
				SanitizedOutput: "",
				ReasonCode:      reasons.OutputSchemaDefer,
				Reason:          reason,
				DeferToken:      token,
			}
		default:
			reason := strings.TrimSpace(cr.rule.Reason)
			if reason == "" {
				reason = fmt.Sprintf("output denied by policy rule %q", cr.rule.ID)
			}
			return GovernOutputResult{
				Outcome:         OutputOutcomeDenied,
				SanitizedOutput: "",
				ReasonCode:      reasons.OutputSchemaDeny,
				Reason:          reason,
			}
		}
	}

	return result
}

func (p *Pipeline) compileOutputRules(outputType string) ([]compiledOutputRule, error) {
	outputType = normalizeOutputType(outputType)
	art := p.currentArtifacts()
	if art == nil || art.engine == nil || art.engine.Doc() == nil {
		return nil, nil
	}
	doc := art.engine.Doc()
	if len(doc.OutputPolicies) == 0 {
		return nil, nil
	}

	out := make([]compiledOutputRule, 0)
	for policyIndex, policy := range doc.OutputPolicies {
		pType := normalizeOutputType(policy.OutputType)
		if pType != outputType {
			continue
		}
		for ruleIndex, rule := range policy.Rules {
			id := normalizeOutputRuleID(strings.TrimSpace(rule.ID), policyIndex, ruleIndex)
			rv := outputRuleView{
				ID:        id,
				Scan:      rule.Scan,
				Condition: strings.TrimSpace(rule.Condition),
				OnMatch:   strings.TrimSpace(rule.OnMatch),
				Reason:    strings.TrimSpace(rule.Reason),
			}
			if rv.Scan == nil {
				rv.Scan = map[string]bool{"entity_extraction": true}
			}
			if err := validateOutputRuleScan(id, rv.Scan); err != nil {
				return nil, err
			}
			onMatch := strings.ToLower(strings.TrimSpace(rv.OnMatch))
			if onMatch == "" {
				return nil, fmt.Errorf("output rule %q missing on_match (supported: deny|defer)", id)
			}
			if onMatch != "deny" && onMatch != "defer" {
				return nil, fmt.Errorf("output rule %q has unsupported on_match %q (supported: deny|defer)", id, rv.OnMatch)
			}
			rv.OnMatch = onMatch

			var program *vm.Program
			if rv.Condition != "" {
				compiled, err := expr.Compile(rv.Condition, expr.Env(outputRuleEvalEnv{}))
				if err != nil {
					return nil, fmt.Errorf("output rule %q compile error: %w", id, err)
				}
				program = compiled
			}
			out = append(out, compiledOutputRule{outputType: pType, rule: rv, program: program})
		}
	}
	return out, nil
}

func (p *Pipeline) evalOutputRule(rule compiledOutputRule, env outputRuleEvalEnv) (bool, error) {
	if rule.program == nil {
		return env.EntityCount > 0, nil
	}
	got, err := vm.Run(rule.program, env)
	if err != nil {
		return false, err
	}
	matched, ok := got.(bool)
	if !ok {
		return false, fmt.Errorf("output rule returned non-bool %T", got)
	}
	return matched, nil
}

func outputEntityTypes(entities []multiagent.EntityExtraction) []string {
	if len(entities) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(entities))
	out := make([]string, 0, len(entities))
	for _, ent := range entities {
		t := strings.TrimSpace(ent.EntityType)
		if t == "" {
			continue
		}
		if _, ok := set[t]; ok {
			continue
		}
		set[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func deterministicOutputDeferToken(agentID, sessionID, outputType, aggregateHash, ruleID string) string {
	seed := strings.Join([]string{
		strings.TrimSpace(agentID),
		strings.TrimSpace(sessionID),
		normalizeOutputType(outputType),
		strings.TrimSpace(aggregateHash),
		strings.TrimSpace(ruleID),
	}, "|")
	if strings.TrimSpace(seed) == "" {
		seed = "output-defer"
	}
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%x", sum[:])[:16]
}

func normalizeOutputType(outputType string) string {
	v := strings.ToLower(strings.TrimSpace(outputType))
	if v == "" {
		return defaultOutputType
	}
	return v
}

func normalizeOutputRuleID(id string, policyIndex, ruleIndex int) string {
	if strings.TrimSpace(id) != "" {
		return strings.TrimSpace(id)
	}
	return fmt.Sprintf("output_%d_%d", policyIndex+1, ruleIndex+1)
}

func validateOutputRuleScan(ruleID string, scan map[string]bool) error {
	for key, enabled := range scan {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			return fmt.Errorf("output rule %q has empty scan key", ruleID)
		}
		if _, ok := allowedOutputScans[normalized]; !ok && enabled {
			return fmt.Errorf("output rule %q has unsupported scan key %q", ruleID, key)
		}
	}
	return nil
}
