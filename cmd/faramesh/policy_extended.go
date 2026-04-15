package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// policy debug — step-through rule evaluation trace.
var policyDebugCmd = &cobra.Command{
	Use:   "debug <policy.yaml>",
	Short: "Show step-by-step rule evaluation for a specific tool call",
	Long: `Trace how each rule is evaluated for a specific tool call, showing
which rules matched, which skipped, and why.

  faramesh policy debug policy.yaml --tool stripe/refund --args '{"amount":500}'
  faramesh policy debug policy.yaml --tool shell/exec --args '{"cmd":"ls"}'

For defer rules, the summary includes approvals_required (distinct approver_ids).

Invaluable for debugging complex policies with many rules.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyDebug,
}

// policy cover — coverage analysis: which tools have no matching rules?
var policyCoverCmd = &cobra.Command{
	Use:   "cover <policy.yaml>",
	Short: "Analyze policy coverage: find tools without matching rules",
	Long: `Check whether all known tools are covered by at least one rule.
Probes a set of synthetic tool IDs plus any tools declared in the policy's
tools: block against the rule patterns.

  faramesh policy cover policies/payment.yaml
  faramesh policy cover policies/payment.yaml --tools stripe/refund,stripe/charge,shell/exec

Tools without a matching rule fall through to the default_effect.
Use this in CI to detect coverage gaps:

  faramesh policy cover policy.yaml || exit 1`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyCover,
}

// policy map — budgets, phases, and rule mix (governance map / token budget surface).
var policyMapCmd = &cobra.Command{
	Use:   "map <policy.yaml|policy.fpl>",
	Short: "Print a governance map for a policy (budgets, phases, rules by effect)",
	Long: `Summarize governance-relevant structure for dashboards and audits: session/daily
budgets, parallel budget caps, declared phases, and counts of rules by effect.

  faramesh policy map policies/payment.yaml

Output is JSON for stable scripting.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyMap,
}

var (
	debugTool          string
	debugArgs          string
	debugUnsafeRawArgs bool
	coverTools         string
)

func init() {
	policyDebugCmd.Flags().StringVar(&debugTool, "tool", "", "tool ID to debug (required)")
	policyDebugCmd.Flags().StringVar(&debugArgs, "args", "{}", "tool arguments as JSON")
	policyDebugCmd.Flags().BoolVar(&debugUnsafeRawArgs, "unsafe-raw-args", false, "print raw argument JSON without redaction")
	_ = policyDebugCmd.MarkFlagRequired("tool")

	policyCoverCmd.Flags().StringVar(&coverTools, "tools", "", "comma-separated tool IDs to check (in addition to declared tools)")

	policyCmd.AddCommand(policyDebugCmd)
	policyCmd.AddCommand(policyCoverCmd)
	policyCmd.AddCommand(policyMapCmd)
}

func runPolicyMap(_ *cobra.Command, args []string) error {
	policyPath := args[0]
	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	phases := make([]string, 0, len(doc.Phases))
	for k := range doc.Phases {
		phases = append(phases, k)
	}
	sort.Strings(phases)

	byEffect := make(map[string]int)
	for _, r := range doc.Rules {
		eff := strings.ToLower(strings.TrimSpace(r.Effect))
		if eff == "" {
			eff = "unspecified"
		}
		byEffect[eff]++
	}

	out := map[string]any{
		"agent_id":                  doc.AgentID,
		"default_effect":            doc.DefaultEffect,
		"phase_names":               phases,
		"rules_total":               len(doc.Rules),
		"rules_by_effect":           byEffect,
		"has_loop_governance":       doc.LoopGovernance != nil,
		"has_defer_priority":        doc.DeferPriority != nil,
		"has_orchestrator_manifest": doc.OrchestratorManifest != nil,
	}
	if doc.Budget != nil {
		out["budget"] = doc.Budget
	}
	if doc.ParallelBudget != nil {
		out["parallel_budget"] = doc.ParallelBudget
	}
	if doc.LoopGovernance != nil {
		out["loop_governance"] = doc.LoopGovernance
	}
	if doc.DeferPriority != nil {
		out["defer_priority"] = doc.DeferPriority
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func runPolicyDebug(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	var toolArgs map[string]any
	if err := json.Unmarshal([]byte(debugArgs), &toolArgs); err != nil {
		return fmt.Errorf("parse --args: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.FgHiBlack)

	fmt.Println()
	bold.Printf("Policy Debug — rule-by-rule trace\n")
	fmt.Printf("  policy : %s [%s]\n", policyPath, version)
	fmt.Printf("  tool   : %s\n", debugTool)
	if debugUnsafeRawArgs {
		fmt.Printf("  args   : %s\n", debugArgs)
	} else {
		fmt.Printf("  args   : %s\n", observe.RedactString(debugArgs))
		dim.Printf("  note   : argument display is redacted by default; use --unsafe-raw-args to print raw values\n")
	}
	fmt.Println()

	// Compile the engine to check for compilation errors.
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	// Step through each rule.
	ctx := policy.EvalContext{
		Args: toolArgs,
		Vars: doc.Vars,
		Tool: policy.ToolCtx{},
	}
	if doc.Tools != nil {
		if t, ok := doc.Tools[debugTool]; ok {
			ctx.Tool = policy.ToolCtx{
				Reversibility: t.Reversibility,
				BlastRadius:   t.BlastRadius,
				Tags:          t.Tags,
			}
		}
	}

	bold.Println("  Rule evaluation trace:")
	fmt.Println()

	result := engine.Evaluate(debugTool, ctx)

	for i, rule := range doc.Rules {
		step := fmt.Sprintf("  [%d]", i)
		toolMatch := matchToolDebug(rule.Match.Tool, debugTool)

		if !toolMatch {
			dim.Printf("  %s %-24s  SKIP  tool=%q does not match %q\n", step, rule.ID, rule.Match.Tool, debugTool)
			continue
		}

		if rule.Match.When == "" {
			if rule.ID == result.RuleID {
				effectColor := ruleEffectColor(rule.Effect)
				effectColor.Printf("  %s %-24s  ▶ %s  (unconditional match, tool=%q)\n", step, rule.ID, strings.ToUpper(rule.Effect), rule.Match.Tool)
			} else {
				dim.Printf("  %s %-24s  SKIP  (earlier rule matched first)\n", step, rule.ID)
			}
			continue
		}

		if rule.ID == result.RuleID {
			effectColor := ruleEffectColor(rule.Effect)
			effectColor.Printf("  %s %-24s  ▶ %s  when=%q → true\n", step, rule.ID, strings.ToUpper(rule.Effect), truncate(rule.Match.When, 50))
		} else {
			dim.Printf("  %s %-24s  SKIP  when=%q → false\n", step, rule.ID, truncate(rule.Match.When, 50))
		}
	}

	fmt.Println()
	bold.Printf("  Result: ")
	switch strings.ToUpper(result.Effect) {
	case "PERMIT", "ALLOW":
		green.Printf("%s", result.Effect)
	case "DENY", "HALT":
		red.Printf("%s", result.Effect)
	case "DEFER":
		yellow.Printf("%s", result.Effect)
	default:
		dim.Printf("%s", result.Effect)
	}
	if result.RuleID != "" {
		fmt.Printf("  (rule: %s)", result.RuleID)
	} else {
		dim.Printf("  (default_effect)")
	}
	fmt.Println()

	if strings.EqualFold(result.Effect, "defer") {
		n := result.ApprovalsRequired
		if n < 1 {
			n = 1
		}
		if result.ApprovalsRequired > 1 {
			yellow.Printf("  Defer control: %d distinct approver_id(s) required (approvals_required).\n", n)
		} else {
			dim.Printf("  Defer control: single approver (default; set approvals_required on the rule for dual/multi control).\n")
		}
	} else if result.ApprovalsRequired > 1 {
		yellow.Printf("  Note: matched rule sets approvals_required=%d (only applies when effect is defer).\n", result.ApprovalsRequired)
	}

	fmt.Println()
	return nil
}

func matchToolDebug(pattern, toolID string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	// Simple prefix glob. For more complex matching use path.Match.
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(toolID, pattern[:len(pattern)-2]+"/") || toolID == pattern[:len(pattern)-2]
	}
	return pattern == toolID
}

func runPolicyCover(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	dim := color.New(color.FgHiBlack)

	// Collect tool IDs to probe.
	probeSet := make(map[string]bool)

	// Add tools declared in the policy.
	for toolID := range doc.Tools {
		probeSet[toolID] = true
	}

	// Add synthetic probes.
	syntheticProbes := []string{
		"http/get", "http/post", "http/put", "http/delete",
		"shell/exec", "shell/run", "shell/bash",
		"stripe/refund", "stripe/charge", "stripe/customer",
		"file/read", "file/write", "file/delete",
		"db/query", "db/insert", "db/update", "db/delete",
		"email/send", "slack/post",
		"aws/s3/put", "aws/lambda/invoke",
		"read_file", "write_file", "search", "browse",
	}
	for _, t := range syntheticProbes {
		probeSet[t] = true
	}

	// Add user-specified tools.
	if coverTools != "" {
		for _, t := range strings.Split(coverTools, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				probeSet[t] = true
			}
		}
	}

	fmt.Println()
	bold.Printf("Policy Coverage Analysis\n")
	fmt.Printf("  policy   : %s\n", policyPath)
	fmt.Printf("  rules    : %d\n", len(doc.Rules))
	fmt.Printf("  probes   : %d tool IDs\n", len(probeSet))
	fmt.Printf("  default  : %s\n", doc.DefaultEffect)
	fmt.Println()

	// Check coverage.
	var covered, uncovered []string
	var ruleHits = make(map[string]int) // ruleID -> hit count

	for toolID := range probeSet {
		matched := false
		for _, rule := range doc.Rules {
			if matchToolDebug(rule.Match.Tool, toolID) {
				matched = true
				ruleHits[rule.ID]++
				break
			}
		}
		if matched {
			covered = append(covered, toolID)
		} else {
			uncovered = append(uncovered, toolID)
		}
	}

	if len(covered) > 0 {
		green.Printf("  ✓ %d tools covered by explicit rules\n", len(covered))
	}

	if len(uncovered) > 0 {
		red.Printf("  ✗ %d tools fall through to default_effect (%s):\n", len(uncovered), doc.DefaultEffect)
		for _, t := range uncovered {
			red.Printf("      %s\n", t)
		}
	}

	// Show rules that never matched any probe (dead rules).
	fmt.Println()
	var deadRules []string
	for _, rule := range doc.Rules {
		if _, hit := ruleHits[rule.ID]; !hit {
			// Check if the rule's pattern would match any probe at all.
			anyMatch := false
			for toolID := range probeSet {
				if matchToolDebug(rule.Match.Tool, toolID) {
					anyMatch = true
					break
				}
			}
			if !anyMatch && rule.Match.Tool != "" && rule.Match.Tool != "*" {
				deadRules = append(deadRules, rule.ID)
			}
		}
	}

	if len(deadRules) > 0 {
		dim.Printf("  ℹ %d rules matched no probed tools (may match unlisted tools):\n", len(deadRules))
		for _, id := range deadRules {
			dim.Printf("      %s\n", id)
		}
	}

	fmt.Println()

	// CI exit code: fail if there are uncovered tools.
	if len(uncovered) > 0 {
		os.Exit(1)
	}
	return nil
}
