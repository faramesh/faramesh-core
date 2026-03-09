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
  faramesh audit tail                       # Stream live decisions
  faramesh auth login                       # Authenticate with Horizon cloud
  faramesh auth status                      # Show Horizon auth status`,
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
	rootCmd.AddCommand(authCmd)

	// Convenience top-level aliases for login/logout/whoami.
	rootCmd.AddCommand(&cobra.Command{
		Use:    "login",
		Short:  "Authenticate with Faramesh Horizon (alias: auth login)",
		Hidden: true,
		RunE:   runAuthLogin,
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:    "logout",
		Short:  "Remove stored Horizon credentials (alias: auth logout)",
		Hidden: true,
		RunE:   authLogoutCmd.RunE,
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:     "whoami",
		Short:   "Show Horizon authentication status (alias: auth status)",
		Hidden:  true,
		Aliases: []string{},
		RunE:    runAuthStatus,
	})

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
