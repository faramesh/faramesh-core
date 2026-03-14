package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
)

// policy replay — replay DPR records against a new policy to predict drift.
var policyReplayCmd = &cobra.Command{
	Use:   "replay <policy.yaml> <dpr.db>",
	Short: "Replay historical decisions against a policy to predict drift",
	Long: `Replay DPR records from the audit database against a policy file.
Shows which decisions would change, enabling safe policy updates.

  faramesh policy replay policies/v2.yaml data/dpr.db
  faramesh policy replay policies/v2.yaml data/dpr.db --limit 1000
  faramesh policy replay policies/v2.yaml data/dpr.db --json

This is the governance equivalent of "terraform plan" — see the impact
of a policy change before deploying it.`,
	Args: cobra.ExactArgs(2),
	RunE: runPolicyReplay,
}

// policy debug — step-through rule evaluation trace.
var policyDebugCmd = &cobra.Command{
	Use:   "debug <policy.yaml>",
	Short: "Show step-by-step rule evaluation for a specific tool call",
	Long: `Trace how each rule is evaluated for a specific tool call, showing
which rules matched, which skipped, and why.

  faramesh policy debug policy.yaml --tool stripe/refund --args '{"amount":500}'
  faramesh policy debug policy.yaml --tool shell/exec --args '{"cmd":"ls"}'

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

var (
	replayLimit int
	replayJSON  bool
	debugTool   string
	debugArgs   string
	debugUnsafeRawArgs bool
	coverTools  string
)

func init() {
	policyReplayCmd.Flags().IntVar(&replayLimit, "limit", 500, "max DPR records to replay")
	policyReplayCmd.Flags().BoolVar(&replayJSON, "json", false, "output drift report as JSON")

	policyDebugCmd.Flags().StringVar(&debugTool, "tool", "", "tool ID to debug (required)")
	policyDebugCmd.Flags().StringVar(&debugArgs, "args", "{}", "tool arguments as JSON")
	policyDebugCmd.Flags().BoolVar(&debugUnsafeRawArgs, "unsafe-raw-args", false, "print raw argument JSON without redaction")
	_ = policyDebugCmd.MarkFlagRequired("tool")

	policyCoverCmd.Flags().StringVar(&coverTools, "tools", "", "comma-separated tool IDs to check (in addition to declared tools)")

	policyCmd.AddCommand(policyReplayCmd)
	policyCmd.AddCommand(policyDebugCmd)
	policyCmd.AddCommand(policyCoverCmd)
}

func runPolicyReplay(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	dbPath := args[1]

	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	records, err := store.Recent(replayLimit)
	if err != nil {
		return fmt.Errorf("read DPR records: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.FgHiBlack)

	pip := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	type driftEntry struct {
		RecordID   string `json:"record_id"`
		ToolID     string `json:"tool_id"`
		AgentID    string `json:"agent_id"`
		OldEffect  string `json:"old_effect"`
		NewEffect  string `json:"new_effect"`
		OldRule    string `json:"old_rule"`
		NewRule    string `json:"new_rule"`
		OldReason  string `json:"old_reason"`
		NewReason  string `json:"new_reason"`
	}

	var drifts []driftEntry
	total := len(records)
	same := 0

	for _, rec := range records {
		req := core.CanonicalActionRequest{
			CallID:    rec.RecordID,
			AgentID:   rec.AgentID,
			SessionID: rec.SessionID,
			ToolID:    rec.ToolID,
			Args:      map[string]any{}, // original args not stored in DPR (privacy)
		}
		newDecision := pip.Evaluate(req)

		if strings.EqualFold(string(newDecision.Effect), rec.Effect) {
			same++
			continue
		}

		drifts = append(drifts, driftEntry{
			RecordID:  rec.RecordID,
			ToolID:    rec.ToolID,
			AgentID:   rec.AgentID,
			OldEffect: rec.Effect,
			NewEffect: string(newDecision.Effect),
			OldRule:   rec.MatchedRuleID,
			NewRule:   newDecision.RuleID,
			OldReason: rec.ReasonCode,
			NewReason: newDecision.ReasonCode,
		})
	}

	if replayJSON {
		out, _ := json.MarshalIndent(map[string]any{
			"total":      total,
			"same":       same,
			"drifted":    len(drifts),
			"drift_pct":  fmt.Sprintf("%.1f%%", float64(len(drifts))/float64(total)*100),
			"drifts":     drifts,
		}, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	fmt.Println()
	bold.Printf("Policy Replay — drift prediction\n")
	fmt.Printf("  policy : %s [%s]\n", policyPath, version)
	fmt.Printf("  source : %s  (%d records)\n", dbPath, total)
	fmt.Println()

	if len(drifts) == 0 {
		green.Printf("  ✓ No drift detected. All %d decisions would be identical.\n\n", total)
		return nil
	}

	yellow.Printf("  ⚠ %d of %d decisions (%.1f%%) would change:\n\n",
		len(drifts), total, float64(len(drifts))/float64(total)*100)

	for _, d := range drifts {
		fmt.Printf("    %-22s  ", d.ToolID)
		red.Printf("%-8s", d.OldEffect)
		fmt.Printf(" → ")
		effectColor := green
		if strings.EqualFold(d.NewEffect, "DENY") {
			effectColor = red
		} else if strings.EqualFold(d.NewEffect, "DEFER") {
			effectColor = yellow
		}
		effectColor.Printf("%-8s", d.NewEffect)
		dim.Printf("  agent=%s\n", d.AgentID)
	}
	fmt.Println()
	return nil
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
