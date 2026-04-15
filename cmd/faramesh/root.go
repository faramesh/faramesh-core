package main

import "github.com/spf13/cobra"

func init() {
	// Top-level commands (subtrees that self-register to root: hub, mcp, sbom, sign, verify).
	for _, c := range []*cobra.Command{
		serveCmd,
		runCmd,
		detectEnvCmd,
		discoverCmd,
		coverageCmd,
		gapsCmd,
		attachCmd,
		suggestCmd,
		setupCmd,
		initCmd,
		onboardCmd,
		offboardCmd,
		demoCmd,
		policyCmd,
		agentCmd,
		auditCmd,
		authCmd,
		chaosCmd,
		compensateCmd,
		complianceCmd,
		explainCmd,
		fleetCmd,
	} {
		rootCmd.AddCommand(c)
	}
}
