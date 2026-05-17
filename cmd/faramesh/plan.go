package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/governance"
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show changes that apply would make",
	Long:  "Compare the current compiled stack with governance.fms and print a change summary.",
	Args:  cobra.NoArgs,
	RunE:  runPlan,
}

func init() {
	planCmd.Flags().StringVar(&stackDirFlag, "dir", "", "stack directory (default: current working directory)")
	planCmd.Flags().BoolVar(&checkSkipEnv, "skip-env", false, "do not require environment variables referenced by env()")
}

func runPlan(_ *cobra.Command, _ []string) error {
	stackDir, err := resolveStackDir()
	if err != nil {
		return err
	}
	path, content, err := governance.FindSource(stackDir)
	if err != nil {
		return err
	}
	doc, _, err := governance.LoadDocument(stackDir)
	if err != nil {
		return err
	}
	diags := governance.Check(doc, governance.CheckOptions{RequireEnv: !checkSkipEnv})
	if governance.HasErrors(diags) {
		governance.PrintDiagnostics(os.Stderr, diags)
		return fmt.Errorf("check failed — fix errors before planning")
	}
	compiled, compileDiags, err := governance.Compile(doc, stackDir, content, governance.CompileOptions{CheckEnv: !checkSkipEnv})
	if len(compileDiags) > 0 {
		governance.PrintDiagnostics(os.Stderr, compileDiags)
	}
	if err != nil {
		return err
	}
	_ = path
	changes, err := governance.Plan(stackDir, compiled)
	if err != nil {
		return err
	}
	for _, ch := range changes {
		fmt.Fprintf(os.Stdout, "  %s %s: %s\n", ch.Action, ch.Resource, ch.Detail)
	}
	return nil
}
