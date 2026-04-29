package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var policyDecompileCmd = &cobra.Command{
	Use:   "decompile <policy.yaml|policy.fpl>",
	Short: "Decompile a policy document to FPL",
	Long: `Converts a policy document (YAML or FPL-loaded policy doc) into FPL source.

This command provides the policy conversion surface for authoring workflows.
Some advanced YAML policy features are not representable by the current FPL
decompiler shape. Use --strict-lossless to fail when lossy conversion would occur.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyDecompile,
}

var (
	policyDecompileOutput         string
	policyDecompileStrictLossless bool
)

func init() {
	policyDecompileCmd.Flags().StringVar(&policyDecompileOutput, "output", "", "write FPL output to file instead of stdout")
	policyDecompileCmd.Flags().BoolVar(&policyDecompileStrictLossless, "strict-lossless", false, "fail when conversion cannot be lossless")
	policyCmd.AddCommand(policyDecompileCmd)
}

type decompilePlan struct {
	AgentID       string
	DefaultEffect string
	Vars          map[string]string
	Phases        map[string][]string
	Rules         []fpl.DecompileRule
	Budget        *fpl.DecompileBudget
	Delegates     []fpl.DecompileDelegate
	Ambient       *fpl.DecompileAmbient
	Selectors     []fpl.DecompileSelector
	Warnings      []string
}

func runPolicyDecompile(_ *cobra.Command, args []string) error {
	doc, _, err := policy.LoadFile(args[0])
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	plan := buildDecompilePlan(doc)
	if policyDecompileStrictLossless && len(plan.Warnings) > 0 {
		return fmt.Errorf("lossy conversion blocked by --strict-lossless: %s", strings.Join(plan.Warnings, "; "))
	}

	out := fpl.DecompileToFPL(
		plan.AgentID,
		plan.DefaultEffect,
		plan.Vars,
		plan.Phases,
		plan.Rules,
		plan.Budget,
		plan.Delegates,
		plan.Ambient,
		plan.Selectors,
	)

	if strings.TrimSpace(policyDecompileOutput) != "" {
		if err := os.WriteFile(policyDecompileOutput, []byte(out), 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "Wrote FPL to %s\n", policyDecompileOutput)
	} else {
		fmt.Print(out)
	}

	if len(plan.Warnings) > 0 {
		color.New(color.FgYellow).Fprintln(os.Stderr, "conversion warnings (lossy fields):")
		for _, w := range plan.Warnings {
			color.New(color.FgYellow).Fprintf(os.Stderr, "  - %s\n", w)
		}
	}

	return nil
}

func buildDecompilePlan(doc *policy.Doc) decompilePlan {
	plan := decompilePlan{
		AgentID:       strings.TrimSpace(doc.AgentID),
		DefaultEffect: strings.TrimSpace(doc.DefaultEffect),
		Vars:          map[string]string{},
		Phases:        map[string][]string{},
		Rules:         make([]fpl.DecompileRule, 0, len(doc.Rules)),
		Warnings:      unsupportedPolicyFeatures(doc),
	}
	if plan.AgentID == "" {
		plan.AgentID = "agent"
		plan.Warnings = append(plan.Warnings, "agent-id was empty; defaulted to \"agent\"")
	}
	if plan.DefaultEffect == "" {
		plan.DefaultEffect = "deny"
	}

	if len(doc.Vars) > 0 {
		keys := make([]string, 0, len(doc.Vars))
		for k := range doc.Vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := doc.Vars[k]
			switch tv := v.(type) {
			case string:
				plan.Vars[k] = tv
			default:
				plan.Vars[k] = fmt.Sprint(tv)
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("vars.%s converted to string", k))
			}
		}
	}

	if len(doc.Phases) > 0 {
		phaseNames := make([]string, 0, len(doc.Phases))
		for name := range doc.Phases {
			phaseNames = append(phaseNames, name)
		}
		sort.Strings(phaseNames)
		for _, name := range phaseNames {
			ph := doc.Phases[name]
			plan.Phases[name] = append([]string(nil), ph.Tools...)
			if strings.TrimSpace(ph.Duration) != "" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("phases.%s.duration is not emitted by current decompiler", name))
			}
			if strings.TrimSpace(ph.Next) != "" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("phases.%s.next is not emitted by current decompiler", name))
			}
		}
	}

	for _, r := range doc.Rules {
		effect := strings.TrimSpace(r.Effect)
		if effect == "" {
			effect = "deny"
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("rule %q had empty effect; defaulted to deny", r.ID))
		}
		tool := strings.TrimSpace(r.Match.Tool)
		if tool == "" {
			tool = "*"
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("rule %q had empty match.tool; defaulted to *", r.ID))
		}
		plan.Rules = append(plan.Rules, fpl.DecompileRule{
			Effect:     effect,
			Tool:       tool,
			When:       strings.TrimSpace(r.Match.When),
			Notify:     strings.TrimSpace(r.Notify),
			Reason:     strings.TrimSpace(r.Reason),
			StrictDeny: strings.HasPrefix(strings.ToUpper(strings.TrimSpace(r.ReasonCode)), "FPL_STRICT_DENY"),
		})
	}

	if doc.Budget != nil {
		plan.Budget = &fpl.DecompileBudget{
			SessionUSD: doc.Budget.SessionUSD,
			DailyUSD:   doc.Budget.DailyUSD,
			MaxCalls:   doc.Budget.MaxCalls,
			OnExceed:   strings.TrimSpace(doc.Budget.OnExceed),
		}
	}

	if len(doc.DelegationPolicies) > 0 {
		for i, d := range doc.DelegationPolicies {
			target := strings.TrimSpace(d.TargetAgent)
			if target == "" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("delegation_policies[%d].target_agent is empty and was skipped", i))
				continue
			}
			ceiling, ceilingWarning := normalizeDecompileDelegateCeiling(d.Ceiling)
			if ceilingWarning != "" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("delegation_policies[%d].ceiling %s", i, ceilingWarning))
			}
			plan.Delegates = append(plan.Delegates, fpl.DecompileDelegate{
				TargetAgent: target,
				Scope:       strings.TrimSpace(d.Scope),
				TTL:         strings.TrimSpace(d.TTL),
				Ceiling:     ceiling,
			})
		}
	}

	if len(doc.ContextGuards) > 0 {
		for i, g := range doc.ContextGuards {
			id := strings.TrimSpace(g.Source)
			source := strings.TrimSpace(g.Endpoint)
			if source == "" {
				source = strings.TrimSpace(g.Source)
			}
			if source == "" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("context_guards[%d] has no source/endpoint and was skipped", i))
				continue
			}
			if id == "" {
				id = fmt.Sprintf("selector-%d", i+1)
			}
			selector := fpl.DecompileSelector{
				ID:            id,
				Source:        source,
				OnUnavailable: normalizeDecompileGuardEffect(g.OnMissing, "deny"),
				OnTimeout:     normalizeDecompileGuardEffect(g.OnStale, normalizeDecompileGuardEffect(g.OnMissing, "deny")),
			}
			if g.MaxAgeSecs > 0 {
				selector.Cache = fmt.Sprintf("%ds", g.MaxAgeSecs)
			}
			plan.Selectors = append(plan.Selectors, selector)
			if len(g.RequiredFields) > 0 {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("context_guards[%d].required_fields are not emitted by current decompiler", i))
			}
			if strings.TrimSpace(g.OnInconsistent) != "" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("context_guards[%d].on_inconsistent is not emitted by current decompiler", i))
			}
		}
	}

	if len(doc.CrossSessionGuards) > 0 {
		ambient := &fpl.DecompileAmbient{Limits: map[string]string{}}
		for i, g := range doc.CrossSessionGuards {
			if !strings.EqualFold(strings.TrimSpace(g.Scope), "principal") {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("cross_session_guards[%d] scope %q is not representable in ambient and was skipped", i, g.Scope))
				continue
			}
			toolPattern := strings.TrimSpace(g.ToolPattern)
			if toolPattern != "" && toolPattern != "*" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("cross_session_guards[%d] tool_pattern %q is not representable in ambient and was skipped", i, g.ToolPattern))
				continue
			}
			window := strings.TrimSpace(g.Window)
			if window != "" && !strings.EqualFold(window, "24h") {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("cross_session_guards[%d] window %q is not representable in ambient and was skipped", i, g.Window))
				continue
			}
			if g.MaxUniqueRecords <= 0 {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("cross_session_guards[%d] max_unique_records must be > 0 and was skipped", i))
				continue
			}

			switch strings.ToLower(strings.TrimSpace(g.Metric)) {
			case "call_count":
				ambient.Limits["max_calls_per_day"] = fmt.Sprintf("%d", g.MaxUniqueRecords)
			case "unique_record_count", "":
				ambient.Limits["max_customers_per_day"] = fmt.Sprintf("%d", g.MaxUniqueRecords)
			case "data_volume_bytes":
				ambient.Limits["max_data_volume"] = formatDecompileByteSize(g.MaxUniqueRecords)
			default:
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("cross_session_guards[%d] metric %q is not representable in ambient and was skipped", i, g.Metric))
				continue
			}

			onExceed := normalizeDecompileGuardEffect(g.OnExceed, "deny")
			if ambient.OnExceed == "" {
				ambient.OnExceed = onExceed
			} else if !strings.EqualFold(ambient.OnExceed, onExceed) {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("cross_session_guards[%d] on_exceed differs (%q); using %q", i, onExceed, ambient.OnExceed))
			}
		}
		if len(ambient.Limits) > 0 || strings.TrimSpace(ambient.OnExceed) != "" {
			plan.Ambient = ambient
		}
	}

	plan.Warnings = dedupeAndSort(plan.Warnings)
	return plan
}

func unsupportedPolicyFeatures(doc *policy.Doc) []string {
	warnings := make([]string, 0, 24)
	add := func(ok bool, msg string) {
		if ok {
			warnings = append(warnings, msg)
		}
	}

	add(len(doc.Tools) > 0, "tools metadata map is not emitted by current decompiler")
	add(len(doc.PostRules) > 0, "post_rules are not emitted by current decompiler")
	add(doc.Session != nil, "session config is not emitted by current decompiler")
	add(doc.Webhooks != nil, "webhooks config is not emitted by current decompiler")
	add(doc.MaxOutputBytes > 0, "max_output_bytes is not emitted by current decompiler")
	add(len(doc.Compensation) > 0, "compensation metadata is not emitted by current decompiler")

	add(len(doc.PhaseTransitions) > 0, "phase_transitions are not emitted by current decompiler")
	add(doc.PhaseEnforcement != nil, "phase_enforcement is not emitted by current decompiler")
	add(doc.SessionStatePolicy != nil, "session_state_policy is not emitted by current decompiler")
	add(doc.DeferPriority != nil, "defer_priority is not emitted by current decompiler")
	add(doc.ParallelBudget != nil, "parallel_budget is not emitted by current decompiler")
	add(doc.LoopGovernance != nil, "loop_governance is not emitted by current decompiler")
	add(doc.OrchestratorManifest != nil, "orchestrator_manifest is not emitted by current decompiler")
	add(len(doc.ToolSchemas) > 0, "tool_schemas are not emitted by current decompiler")
	add(len(doc.ChainPolicies) > 0, "chain_policies are not emitted by current decompiler")
	add(len(doc.OutputPolicies) > 0, "output_policies are not emitted by current decompiler")
	add(doc.ExecutionIsolation != nil, "execution_isolation is not emitted by current decompiler")

	return warnings
}

func normalizeDecompileGuardEffect(raw, fallback string) string {
	effect := strings.ToLower(strings.TrimSpace(raw))
	if effect == "deny" || effect == "defer" {
		return effect
	}
	return strings.ToLower(strings.TrimSpace(fallback))
}

func normalizeDecompileDelegateCeiling(raw string) (value string, warning string) {
	ceiling := strings.TrimSpace(raw)
	if ceiling == "" {
		return "", ""
	}
	v := strings.ToLower(ceiling)
	if v == "inherited" || v == "approval" {
		return v, ""
	}
	return "approval", fmt.Sprintf("%q is not runtime-loadable in FPL; emitted \"approval\" (fail-closed)", ceiling)
}

func formatDecompileByteSize(v int) string {
	if v <= 0 {
		return "0"
	}
	if v%(1024*1024*1024) == 0 {
		return fmt.Sprintf("%dgb", v/(1024*1024*1024))
	}
	if v%(1024*1024) == 0 {
		return fmt.Sprintf("%dmb", v/(1024*1024))
	}
	if v%1024 == 0 {
		return fmt.Sprintf("%dkb", v/1024)
	}
	return fmt.Sprintf("%db", v)
}

func dedupeAndSort(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(items))
	for _, v := range items {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
