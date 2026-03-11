package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain [dpr-record-id]",
	Short: "Explain why a tool call was denied or deferred",
	Long: `Provide a human-readable explanation of why a specific governance decision
was made. Shows the matching rule, evaluated conditions, and contextual
factors that led to the decision.

Example:
  faramesh explain dpr-abc123
  faramesh explain --last       # Explain the most recent decision
  faramesh explain --last-deny  # Explain the most recent denial`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

var (
	explainLast     bool
	explainLastDeny bool
)

func init() {
	explainCmd.Flags().BoolVar(&explainLast, "last", false, "Explain the most recent decision")
	explainCmd.Flags().BoolVar(&explainLastDeny, "last-deny", false, "Explain the most recent denial")
	rootCmd.AddCommand(explainCmd)
}

func runExplain(_ *cobra.Command, args []string) error {
	bold := color.New(color.Bold)

	if len(args) == 0 && !explainLast && !explainLastDeny {
		return fmt.Errorf("specify a DPR record ID, --last, or --last-deny")
	}

	var recordID string
	if explainLast {
		bold.Println("Explaining most recent decision...")
		recordID = "(most recent)"
	} else if explainLastDeny {
		bold.Println("Explaining most recent denial...")
		recordID = "(most recent denial)"
	} else {
		recordID = args[0]
		bold.Printf("Explaining decision: %s\n", recordID)
	}
	fmt.Println()

	// In production, looks up DPR record and reconstructs the decision.
	fmt.Println("┌─────────────────────────────────────────────────────┐")
	fmt.Printf("│  Record:    %s\n", recordID)
	fmt.Println("│  Effect:    (requires DPR backend)")
	fmt.Println("│  Rule:      (requires DPR backend)")
	fmt.Println("│  Reason:    (requires DPR backend)")
	fmt.Println("│")
	fmt.Println("│  Conditions evaluated:")
	fmt.Println("│    (requires DPR backend to reconstruct)")
	fmt.Println("│")
	fmt.Println("│  Context factors:")
	fmt.Println("│    (requires DPR backend to reconstruct)")
	fmt.Println("└─────────────────────────────────────────────────────┘")
	fmt.Println()
	color.Yellow("⚠ Requires DPR backend (pass --dpr-dsn to faramesh serve)")

	return nil
}
