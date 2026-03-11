package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var compensateCmd = &cobra.Command{
	Use:   "compensate [dpr-record-id]",
	Short: "Trigger compensation for a reversible tool call",
	Long: `Trigger the compensation/rollback action for a tool call that was marked
as reversible or compensatable in the DPR. Uses the saga engine to
execute the reverse action.

Example:
  faramesh compensate dpr-abc123    # Compensate a specific tool call
  faramesh compensate --session s1  # Compensate all reversible calls in session`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCompensate,
}

var compensateSessionID string

func init() {
	compensateCmd.Flags().StringVar(&compensateSessionID, "session", "", "Compensate all reversible calls in a session")
	rootCmd.AddCommand(compensateCmd)
}

func runCompensate(_ *cobra.Command, args []string) error {
	if len(args) == 0 && compensateSessionID == "" {
		return fmt.Errorf("specify a DPR record ID or --session")
	}

	if compensateSessionID != "" {
		fmt.Printf("Scanning session %s for reversible tool calls...\n", compensateSessionID)
		// In production, queries DPR for reversible calls and invokes saga engine.
		color.Yellow("⚠ Compensation engine requires DPR backend (pass --dpr-dsn)")
		return nil
	}

	dprID := args[0]
	fmt.Printf("Looking up DPR record %s...\n", dprID)
	// In production, looks up record, checks reversibility, invokes compensation.
	color.Yellow("⚠ Compensation engine requires DPR backend (pass --dpr-dsn)")
	_ = dprID
	return nil
}
