package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

var policySimulateCmd = &cobra.Command{
	Use:   "simulate <policy.fpl|policy.yaml>",
	Short: "Simulate policy decision with deterministic trace output",
	Long: `Evaluate a simulated governed tool call against a policy and emit
a decision trace suitable for control-plane UX and CI diagnostics.

This command is the core policy simulation surface for hosted/backend flows.

  faramesh policy simulate policy.fpl --tool stripe/refund --args '{"amount":500}'
  faramesh policy simulate policy.fpl --tool stripe/refund --mode deny --risk-score 0.95 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicySimulate,
}

type policySimulateTraceStep struct {
	Step    string `json:"step"`
	Outcome string `json:"outcome"`
}

type policySimulateReport struct {
	Decision       string                    `json:"decision"`
	Effect         string                    `json:"effect"`
	Reason         string                    `json:"reason"`
	RuleID         string                    `json:"rule_id,omitempty"`
	MatchedRuleIDs []string                  `json:"matched_rule_ids"`
	Trace          []policySimulateTraceStep `json:"trace"`
	PolicyPath     string                    `json:"policy_path"`
	PolicyVersion  string                    `json:"policy_version,omitempty"`
	Warnings       []string                  `json:"warnings,omitempty"`
}

var (
	policySimulateTool      string
	policySimulateArgs      string
	policySimulateMode      string
	policySimulateRiskScore float64
	policySimulateActorRole string
	policySimulateAgent     string
	policySimulateSession   string
	policySimulateJSON      bool
)

func init() {
	policySimulateCmd.Flags().StringVar(&policySimulateTool, "tool", "", "tool ID to simulate (required)")
	policySimulateCmd.Flags().StringVar(&policySimulateArgs, "args", "{}", "tool arguments as JSON object")
	policySimulateCmd.Flags().StringVar(&policySimulateMode, "mode", "allow", "requested simulation mode: allow|deny|defer")
	policySimulateCmd.Flags().Float64Var(&policySimulateRiskScore, "risk-score", -1, "optional risk score signal in [0,1] injected into args.risk_score")
	policySimulateCmd.Flags().StringVar(&policySimulateActorRole, "actor-role", "", "optional actor role signal injected into args.actor_role")
	policySimulateCmd.Flags().StringVar(&policySimulateAgent, "agent", "policy-sim-agent", "agent ID for simulation context")
	policySimulateCmd.Flags().StringVar(&policySimulateSession, "session", "policy-sim-session", "session ID for simulation context")
	policySimulateCmd.Flags().BoolVar(&policySimulateJSON, "json", false, "emit machine-readable JSON simulation report")
	_ = policySimulateCmd.MarkFlagRequired("tool")

	policyCmd.AddCommand(policySimulateCmd)
}

func runPolicySimulate(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	requestedMode := strings.ToLower(strings.TrimSpace(policySimulateMode))
	if requestedMode != "allow" && requestedMode != "deny" && requestedMode != "defer" {
		return fmt.Errorf("invalid --mode %q (expected allow|deny|defer)", policySimulateMode)
	}

	if policySimulateRiskScore > 1 {
		return fmt.Errorf("--risk-score must be <= 1")
	}
	if policySimulateRiskScore != -1 && policySimulateRiskScore < 0 {
		return fmt.Errorf("--risk-score must be >= 0 or omitted")
	}

	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	hardErrors, warnings := splitValidationDiagnostics(policy.Validate(doc))
	if len(hardErrors) > 0 {
		return fmt.Errorf("policy validation failed: %s", strings.Join(hardErrors, " | "))
	}

	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	var toolArgs map[string]any
	if err := json.Unmarshal([]byte(policySimulateArgs), &toolArgs); err != nil {
		return fmt.Errorf("parse --args: %w", err)
	}
	if toolArgs == nil {
		toolArgs = map[string]any{}
	}
	if _, exists := toolArgs["simulation_mode"]; !exists {
		toolArgs["simulation_mode"] = requestedMode
	}
	if policySimulateRiskScore >= 0 {
		toolArgs["risk_score"] = policySimulateRiskScore
	}
	if strings.TrimSpace(policySimulateActorRole) != "" {
		toolArgs["actor_role"] = strings.TrimSpace(policySimulateActorRole)
	}

	pip := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	req := core.CanonicalActionRequest{
		CallID:           "policy-simulate",
		AgentID:          policySimulateAgent,
		SessionID:        policySimulateSession,
		ToolID:           policySimulateTool,
		Args:             toolArgs,
		InterceptAdapter: "cli",
	}
	d := pip.Evaluate(req)

	decision := mapEffectToSimulationDecision(d.Effect)
	matchedRuleIDs := make([]string, 0, 1)
	if strings.TrimSpace(d.RuleID) != "" {
		matchedRuleIDs = append(matchedRuleIDs, d.RuleID)
	}

	reason := strings.TrimSpace(d.Reason)
	if reason == "" {
		reason = "simulation completed"
	}

	trace := []policySimulateTraceStep{
		{
			Step:    "policy_parse",
			Outcome: fmt.Sprintf("loaded policy version=%s rules=%d", strings.TrimSpace(version), len(doc.Rules)),
		},
		{
			Step: "input_eval",
			Outcome: fmt.Sprintf(
				"tool=%s requested_mode=%s risk_score=%s actor_role=%s args_keys=%d",
				policySimulateTool,
				requestedMode,
				riskScoreLabel(policySimulateRiskScore),
				or(strings.TrimSpace(policySimulateActorRole), "n/a"),
				len(toolArgs),
			),
		},
		{
			Step:    "decision",
			Outcome: fmt.Sprintf("effect=%s decision=%s requested_mode=%s reason_code=%s", d.Effect, decision, requestedMode, or(d.ReasonCode, "n/a")),
		},
	}
	if len(matchedRuleIDs) > 0 {
		trace = append(trace, policySimulateTraceStep{Step: "rule_match", Outcome: fmt.Sprintf("matched %d rule(s): %s", len(matchedRuleIDs), strings.Join(matchedRuleIDs, ", "))})
	} else {
		trace = append(trace, policySimulateTraceStep{Step: "rule_match", Outcome: "no explicit rule match; default effect path applied"})
	}

	report := policySimulateReport{
		Decision:       decision,
		Effect:         strings.ToUpper(string(d.Effect)),
		Reason:         reason,
		RuleID:         d.RuleID,
		MatchedRuleIDs: matchedRuleIDs,
		Trace:          trace,
		PolicyPath:     policyPath,
		PolicyVersion:  strings.TrimSpace(version),
		Warnings:       warnings,
	}

	if policySimulateJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encode simulation report: %w", err)
		}
		return nil
	}

	bold := color.New(color.Bold)
	effectColor := ruleEffectColor(strings.ToLower(decision))

	fmt.Println()
	bold.Printf("  Tool:      ")
	fmt.Printf("%s\n", policySimulateTool)
	bold.Printf("  Decision:  ")
	effectColor.Printf("%s\n", strings.ToUpper(decision))
	bold.Printf("  Rule:      ")
	fmt.Printf("%s\n", or(d.RuleID, "(default_effect path)"))
	bold.Printf("  Reason:    ")
	fmt.Printf("%s\n", report.Reason)
	if len(warnings) > 0 {
		bold.Printf("  Warnings:  ")
		fmt.Printf("%d\n", len(warnings))
	}
	fmt.Println()
	bold.Println("  Trace:")
	for _, step := range report.Trace {
		fmt.Printf("    - %s: %s\n", step.Step, step.Outcome)
	}
	fmt.Println()

	return nil
}

func mapEffectToSimulationDecision(effect core.Effect) string {
	switch strings.ToUpper(string(effect)) {
	case "PERMIT", "ALLOW", "SHADOW_PERMIT":
		return "allow"
	case "DEFER", "ABSTAIN":
		return "defer"
	case "DENY", "HALT", "SHADOW":
		return "deny"
	default:
		return "deny"
	}
}

func riskScoreLabel(v float64) string {
	if v < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", v)
}
