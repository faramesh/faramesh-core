package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy lifecycle: validate, test, and inspect policy files",
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate <policy.yaml>",
	Short: "Validate a policy file",
	Long: `faramesh policy validate parses the policy YAML, validates rule structure,
and compiles all when-conditions with expr-lang. Exits 0 on success, 1 on error.

Use this in CI to catch policy errors before deployment:
  faramesh policy validate policies/payment.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyValidate,
}

var policyInspectCmd = &cobra.Command{
	Use:   "inspect <policy.yaml>",
	Short: "Show compiled policy summary",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyInspect,
}

func init() {
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyInspectCmd)
}

func runPolicyValidate(cmd *cobra.Command, args []string) error {
	path := args[0]
	doc, version, err := policy.LoadFile(path)
	if err != nil {
		printError("parse error: " + err.Error())
		os.Exit(1)
	}

	errs := policy.Validate(doc)
	if len(errs) > 0 {
		for _, e := range errs {
			printError(e)
		}
		os.Exit(1)
	}

	// Attempt full compilation.
	if _, err := policy.NewEngine(doc, version); err != nil {
		printError("compilation error: " + err.Error())
		os.Exit(1)
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("✓ ")
	fmt.Printf("%s  ", path)
	color.New(color.FgHiBlack).Printf("[%s]  ", version)
	fmt.Printf("%d rules  agent=%s\n", len(doc.Rules), doc.AgentID)
	return nil
}

func runPolicyInspect(cmd *cobra.Command, args []string) error {
	path := args[0]
	doc, version, err := policy.LoadFile(path)
	if err != nil {
		return err
	}

	bold := color.New(color.Bold)
	dim := color.New(color.FgHiBlack)

	bold.Printf("Policy: %s\n", path)
	fmt.Printf("  version    : %s\n", version)
	fmt.Printf("  agent-id   : %s\n", doc.AgentID)
	fmt.Printf("  fpl        : %s\n", doc.FarameshVersion)
	fmt.Printf("  rules      : %d\n", len(doc.Rules))
	fmt.Printf("  tools      : %d declared\n", len(doc.Tools))
	fmt.Printf("  default    : %s\n", doc.DefaultEffect)

	if len(doc.Rules) > 0 {
		fmt.Println()
		bold.Println("Rules:")
		for _, r := range doc.Rules {
			effectColor := ruleEffectColor(r.Effect)
			effectColor.Printf("  %-8s", r.Effect)
			fmt.Printf(" %-32s", r.ID)
			if r.Match.Tool != "" {
				dim.Printf("  tool=%s", r.Match.Tool)
			}
			if r.Match.When != "" {
				dim.Printf("  when=%q", truncate(r.Match.When, 40))
			}
			fmt.Println()
		}
	}
	return nil
}

func ruleEffectColor(effect string) *color.Color {
	switch effect {
	case "permit", "allow":
		return color.New(color.FgGreen)
	case "deny", "halt":
		return color.New(color.FgRed)
	case "defer", "abstain":
		return color.New(color.FgYellow)
	default:
		return color.New(color.FgHiBlack)
	}
}

func printError(msg string) {
	color.New(color.FgRed, color.Bold).Printf("✗ ")
	fmt.Println(msg)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
