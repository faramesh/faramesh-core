package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var policyFplJSON bool

var policyFplCmd = &cobra.Command{
	Use:   "fpl [file.fpl]",
	Short: "Parse and compile Faramesh Policy Language (FPL) rules",
	Long: `Reads FPL source and prints compiled IR (policy-ready). Use "-" or omit file to read stdin.

This supports ONE_PLAN P4 (FPL depth) and release acceptance for the FPL compiler surface.

Topology (orchestrator_manifest) lines may appear alongside rules:
  manifest orchestrator <id> undeclared deny|defer
  manifest grant <id> to <target> max <n>
  manifest grant <id> to <target> max <n> approval
  (approval-only with unlimited cap: max 0 approval)

  faramesh policy fpl rules.fpl
  cat rules.fpl | faramesh policy fpl -
  faramesh policy fpl --json rules.fpl`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPolicyFPL,
}

func init() {
	policyFplCmd.Flags().BoolVar(&policyFplJSON, "json", false, "emit compiled rules as JSON")
	policyCmd.AddCommand(policyFplCmd)
}

func runPolicyFPL(cmd *cobra.Command, args []string) error {
	var src []byte
	var err error
	switch {
	case len(args) == 0:
		src, err = io.ReadAll(os.Stdin)
	case args[0] == "-":
		src, err = io.ReadAll(os.Stdin)
	default:
		src, err = os.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("read FPL: %w", err)
	}

	parsed, err := fpl.ParseProgram(string(src))
	if err != nil {
		return fmt.Errorf("parse FPL: %w", err)
	}
	compiled, err := fpl.CompileRules(parsed.Rules)
	if err != nil {
		return fmt.Errorf("compile FPL rules: %w", err)
	}

	if policyFplJSON {
		topo, err := policy.PreviewOrchestratorManifestFromFPLStatements(parsed.Topo)
		if err != nil {
			return fmt.Errorf("compile FPL topology: %w", err)
		}
		out := struct {
			Rules    []*fpl.CompiledRule `json:"rules"`
			Topology any                 `json:"topology"`
		}{
			Rules:    compiled,
			Topology: fplTopologyJSON(topo),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	bold := color.New(color.Bold)
	bold.Printf("%d compiled rule(s)\n\n", len(compiled))
	if len(parsed.Topo) > 0 {
		topo, err := policy.PreviewOrchestratorManifestFromFPLStatements(parsed.Topo)
		if err != nil {
			return fmt.Errorf("compile FPL topology: %w", err)
		}
		if topo != nil {
			fmt.Printf("topology: orchestrator_id=%s undeclared=%s entries=%d\n\n",
				topo.AgentID, topo.UndeclaredInvocationPolicy, len(topo.PermittedInvocations))
		}
	}
	for i, r := range compiled {
		fmt.Printf("  [%d] effect=%s tool=%s\n", i+1, r.Effect, r.Tool)
		if r.When != "" {
			fmt.Printf("       when=%s\n", r.When)
		}
		if r.ReasonCode != "" {
			fmt.Printf("       reason_code=%s\n", r.ReasonCode)
		}
		if r.Reason != "" {
			fmt.Printf("       reason=%s\n", r.Reason)
		}
		if r.Notify != nil {
			fmt.Printf("       notify=%s\n", r.Notify.Target)
		}
		if r.StrictDeny {
			fmt.Printf("       strict_deny=true\n")
		}
		fmt.Println()
	}
	return nil
}
