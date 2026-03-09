package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags.
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "faramesh",
	Short: "Unified governance plane for AI agents",
	Long: `Faramesh is a unified governance plane for AI agents: pre-execution
authorization, policy-as-code enforcement, tamper-evident audit trail.

One binary. One policy language. One DPR chain. Every environment.

Quick start:
  faramesh demo                             # See governance in action
  faramesh init                             # Detect env, generate config
  faramesh serve --policy policy.yaml      # Start the daemon
  faramesh policy validate policy.yaml     # Validate a policy file
  faramesh audit tail                       # Stream live decisions`,
	SilenceUsage: true,
	Version:      version,
}

func init() {
	rootCmd.AddCommand(demoCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(agentCmd)

	rootCmd.SetVersionTemplate(func() string {
		bold := color.New(color.Bold)
		return bold.Sprintf("faramesh %s\n", version)
	}())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
