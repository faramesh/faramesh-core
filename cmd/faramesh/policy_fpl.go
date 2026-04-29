package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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

var policyFplDecompileCmd = &cobra.Command{
	Use:   "decompile <policy.yaml|policy.fpl>",
	Short: "Decompile policy YAML/FPL to canonical FPL source",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyFPLDecompile,
}

var policyFplYAMLCmd = &cobra.Command{
	Use:   "yaml <policy.fpl>",
	Short: "Convert FPL policy to equivalent YAML",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyFPLYAML,
}

func init() {
	policyFplCmd.Flags().BoolVar(&policyFplJSON, "json", false, "emit compiled rules as JSON")
	policyFplCmd.AddCommand(policyFplDecompileCmd)
	policyFplCmd.AddCommand(policyFplYAMLCmd)
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

func runPolicyFPLDecompile(_ *cobra.Command, args []string) error {
	inputPath := strings.TrimSpace(args[0])
	if strings.HasSuffix(strings.ToLower(inputPath), ".fpl") {
		raw, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("read FPL: %w", err)
		}
		fmt.Print(strings.TrimRight(string(raw), "\n"))
		fmt.Println()
		return nil
	}

	if src, err := maybeInlineFPLFromYAML(args[0]); err != nil {
		return err
	} else if strings.TrimSpace(src) != "" {
		fmt.Print(strings.TrimRight(src, "\n"))
		fmt.Println()
		return nil
	}

	doc, _, err := policy.LoadFile(args[0])
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	out := fpl.DecompileToFPL(
		doc.AgentID,
		doc.DefaultEffect,
		decompileVars(doc.Vars),
		decompilePhases(doc.Phases),
		decompileRules(doc.Rules),
		decompileBudget(doc.Budget),
		nil,
		nil,
		nil,
	)
	fmt.Print(out)
	return nil
}

func runPolicyFPLYAML(_ *cobra.Command, args []string) error {
	path := args[0]
	if !strings.HasSuffix(strings.ToLower(path), ".fpl") {
		return fmt.Errorf("policy fpl yaml expects an .fpl input file")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read FPL policy: %w", err)
	}

	doc, _, err := policy.LoadFile(path)
	if err != nil {
		return fmt.Errorf("load FPL policy: %w", err)
	}

	bridge := fplInlineBridgeYAML{
		FarameshVersion: doc.FarameshVersion,
		AgentID:         doc.AgentID,
		DefaultEffect:   doc.DefaultEffect,
		FPLInline:       string(raw),
	}
	out, err := yaml.Marshal(bridge)
	if err != nil {
		return fmt.Errorf("marshal YAML: %w", err)
	}
	fmt.Print(string(out))
	return nil
}

func maybeInlineFPLFromYAML(path string) (string, error) {
	lower := strings.ToLower(strings.TrimSpace(path))
	if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read policy: %w", err)
	}
	var bridge fplInlineBridgeYAML
	if err := yaml.Unmarshal(raw, &bridge); err != nil {
		return "", fmt.Errorf("parse policy yaml: %w", err)
	}
	return bridge.FPLInline, nil
}

func decompileVars(vars map[string]any) map[string]string {
	if len(vars) == 0 {
		return nil
	}
	out := make(map[string]string, len(vars))
	for k, v := range vars {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func decompilePhases(phases map[string]policy.Phase) map[string][]string {
	if len(phases) == 0 {
		return nil
	}
	out := make(map[string][]string, len(phases))
	for name, ph := range phases {
		tools := append([]string(nil), ph.Tools...)
		sort.Strings(tools)
		out[name] = tools
	}
	return out
}

func decompileRules(rules []policy.Rule) []fpl.DecompileRule {
	out := make([]fpl.DecompileRule, 0, len(rules))
	for _, r := range rules {
		strict := strings.HasPrefix(strings.ToUpper(strings.TrimSpace(r.ReasonCode)), "FPL_STRICT_DENY")
		out = append(out, fpl.DecompileRule{
			Effect:     strings.TrimSpace(r.Effect),
			Tool:       strings.TrimSpace(r.Match.Tool),
			When:       strings.TrimSpace(r.Match.When),
			Notify:     strings.TrimSpace(r.Notify),
			Reason:     strings.TrimSpace(r.Reason),
			StrictDeny: strict,
		})
	}
	return out
}

func decompileBudget(b *policy.Budget) *fpl.DecompileBudget {
	if b == nil {
		return nil
	}
	return &fpl.DecompileBudget{
		SessionUSD: b.SessionUSD,
		DailyUSD:   b.DailyUSD,
		MaxCalls:   b.MaxCalls,
		OnExceed:   b.OnExceed,
	}
}

type fplInlineBridgeYAML struct {
	FarameshVersion string `yaml:"faramesh-version,omitempty"`
	AgentID         string `yaml:"agent-id,omitempty"`
	DefaultEffect   string `yaml:"default_effect,omitempty"`
	FPLInline       string `yaml:"fpl_inline,omitempty"`
}
