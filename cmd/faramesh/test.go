package main

import (
	"fmt"
	"os"

	"github.com/faramesh/faramesh-core/internal/core/governance"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Validate governance.fms without starting the daemon",
	Long:  "Runs check and compile; exits non-zero when validation fails.",
	Args:  cobra.NoArgs,
	RunE:  runTest,
}

func init() {
	testCmd.Flags().StringVar(&stackDirFlag, "dir", "", "stack directory")
}

func runTest(_ *cobra.Command, _ []string) error {
	stackDir, err := resolveStackDir()
	if err != nil {
		return err
	}
	doc, _, err := governance.LoadDocument(stackDir)
	if err != nil {
		return err
	}
	diags := governance.Check(doc, governance.CheckOptions{RequireEnv: false})
	if len(diags) > 0 {
		governance.PrintDiagnostics(os.Stderr, diags)
	}
	if governance.HasErrors(diags) {
		return fmt.Errorf("governance check failed")
	}
	_, content, err := governance.FindSource(stackDir)
	if err != nil {
		return err
	}
	_, diags, err = governance.Compile(doc, stackDir, content, governance.CompileOptions{})
	if len(diags) > 0 {
		governance.PrintDiagnostics(os.Stderr, diags)
	}
	if err != nil || governance.HasErrors(diags) {
		return fmt.Errorf("governance compile failed")
	}
	fmt.Println("✓ governance stack is valid")
	return nil
}
