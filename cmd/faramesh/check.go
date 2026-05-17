package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/governance"
)

var (
	checkCmd = &cobra.Command{
		Use:   "check",
		Short: "Validate governance.fms without applying",
		Long:  "Statically validate the governance stack: imports, providers, credentials, env references, and policy shape.",
		Args:  cobra.NoArgs,
		RunE:  runCheck,
	}
	checkSkipEnv bool
)

func init() {
	checkCmd.Flags().StringVar(&stackDirFlag, "dir", "", "stack directory (default: current working directory)")
	checkCmd.Flags().BoolVar(&checkSkipEnv, "skip-env", false, "do not require environment variables referenced by env()")
}

func runCheck(_ *cobra.Command, _ []string) error {
	stackDir, err := resolveStackDir()
	if err != nil {
		return err
	}
	doc, _, err := governance.LoadDocument(stackDir)
	if err != nil {
		return err
	}
	diags := governance.Check(doc, governance.CheckOptions{RequireEnv: !checkSkipEnv})
	if len(diags) > 0 {
		governance.PrintDiagnostics(os.Stderr, diags)
	}
	if governance.HasErrors(diags) {
		return fmt.Errorf("check failed")
	}
	if err := governance.ResolveImports(doc, false); err != nil {
		return err
	}
	if err := governance.RecordProviderImports(doc); err != nil {
		return err
	}
	printCheckOK()
	return nil
}
