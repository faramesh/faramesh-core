package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/faramesh/faramesh-core/internal/core/governance"
	"github.com/spf13/cobra"
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Restore the previous compiled governance artifact",
	Long:  "Swaps governance.compiled.json with governance.compiled.json.bak when present.",
	Args:  cobra.NoArgs,
	RunE:  runRollback,
}

func init() {
	rollbackCmd.Flags().StringVar(&stackDirFlag, "dir", "", "stack directory")
}

func runRollback(_ *cobra.Command, _ []string) error {
	stackDir, err := resolveStackDir()
	if err != nil {
		return err
	}
	cur := governance.CompiledPath(stackDir)
	bak := cur + ".bak"
	if _, err := os.Stat(bak); err != nil {
		return fmt.Errorf("no rollback snapshot at %s (apply creates .bak on recompile)", bak)
	}
	policyBak := filepath.Join(stackDir, "governance.policy.fpl.bak")
	if err := swapFiles(cur, bak); err != nil {
		return err
	}
	if _, err := os.Stat(policyBak); err == nil {
		policyCur := filepath.Join(stackDir, "governance.policy.fpl")
		if err := swapFiles(policyCur, policyBak); err != nil {
			return err
		}
	}
	fmt.Println("✓ rolled back to previous compiled governance")
	fmt.Println("  Run: faramesh apply")
	return nil
}

func swapFiles(a, b string) error {
	tmp := a + ".swap"
	if err := os.Rename(a, tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(b, a); err != nil {
		return err
	}
	return os.Rename(tmp, b)
}
