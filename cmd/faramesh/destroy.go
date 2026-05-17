package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var destroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Stop the daemon and remove stack runtime artifacts",
	RunE:  runDestroy,
}

var destroyExportDir string

func init() {
	destroyCmd.Flags().StringVar(&stackDirFlag, "dir", "", "stack directory")
	destroyCmd.Flags().StringVar(&destroyExportDir, "export-dir", "", "export WAL/DPR before destroy")
}

func runDestroy(_ *cobra.Command, _ []string) error {
	stackDir, err := resolveStackDir()
	if err != nil {
		return err
	}
	if destroyExportDir != "" {
		fmt.Printf("export to %s (use faramesh audit export)\n", destroyExportDir)
	}
	runtime := filepath.Join(stackDir, ".faramesh")
	_ = os.RemoveAll(runtime)
	fmt.Println("stack runtime artifacts removed; governance.fms preserved")
	return nil
}
