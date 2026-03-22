package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

var policyCompileNLPCmd = &cobra.Command{
	Use:   "compile <natural-language-policy>",
	Short: "Compile natural language policy description to FPL",
	Long: `Compiles a natural language policy description into Faramesh Policy Language (FPL)
using pattern-matching NLP. The resulting FPL can be saved to a file or printed to stdout.

Examples:
  faramesh policy compile "deny all shell commands"
  faramesh policy compile --agent my-agent "allow refunds under $100, defer refunds over $500"
  faramesh policy compile --output policy.fpl "block shell, approve reads"`,
	Args: cobra.MinimumNArgs(1),
	RunE: runPolicyCompileNLP,
}

var (
	policyCompileAgent  string
	policyCompileOutput string
)

func init() {
	policyCompileNLPCmd.Flags().StringVar(&policyCompileAgent, "agent", "", "agent identifier for the generated policy")
	policyCompileNLPCmd.Flags().StringVar(&policyCompileOutput, "output", "", "write FPL to file instead of stdout")

	policyCmd.AddCommand(policyCompileNLPCmd)
}

func runPolicyCompileNLP(_ *cobra.Command, args []string) error {
	input := strings.Join(args, " ")
	result := fpl.NLPToFPL(policyCompileAgent, input)

	if policyCompileOutput != "" {
		if err := os.WriteFile(policyCompileOutput, []byte(result), 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		color.New(color.Bold, color.FgGreen).Fprintf(os.Stdout, "✓ FPL written to %s\n", policyCompileOutput)
		return nil
	}

	fmt.Print(result)
	return nil
}
