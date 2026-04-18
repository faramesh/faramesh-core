package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

type commandTier string

const (
	commandTierStable   commandTier = "stable"
	commandTierAdvanced commandTier = "advanced"
	commandTierInternal commandTier = "internal"
)

var commandTierByName = map[string]commandTier{
	"agent":      commandTierStable,
	"attach":     commandTierStable,
	"approvals":  commandTierStable,
	"audit":      commandTierStable,
	"auth":       commandTierStable,
	"chaos-test": commandTierInternal,
	"completion": commandTierStable,
	"compliance": commandTierAdvanced,
	"compensate": commandTierInternal,
	"coverage":   commandTierStable,
	"credential": commandTierStable,
	"delegate":   commandTierInternal,
	"demo":       commandTierInternal,
	"detect":     commandTierAdvanced,
	"discover":   commandTierStable,
	"down":       commandTierStable,
	"explain":    commandTierAdvanced,
	"federation": commandTierInternal,
	"fleet":      commandTierAdvanced,
	"gaps":       commandTierStable,
	"help":       commandTierStable,
	"hub":        commandTierInternal,
	"identity":   commandTierInternal,
	"incident":   commandTierInternal,
	"init":       commandTierAdvanced,
	"mcp":        commandTierStable,
	"model":      commandTierInternal,
	"offboard":   commandTierAdvanced,
	"onboard":    commandTierAdvanced,
	"ops":        commandTierInternal,
	"pack":       commandTierStable,
	"policy":     commandTierStable,
	"provenance": commandTierInternal,
	"run":        commandTierStable,
	"sbom":       commandTierInternal,
	"schedule":   commandTierInternal,
	"serve":      commandTierAdvanced,
	"session":    commandTierInternal,
	"setup":      commandTierStable,
	"sign":       commandTierInternal,
	"start":      commandTierStable,
	"status":     commandTierStable,
	"stop":       commandTierStable,
	"suggest":    commandTierStable,
	"up":         commandTierStable,
	"verify":     commandTierInternal,
}

var commandGroups = []*cobra.Group{
	{ID: string(commandTierStable), Title: "Stable Commands"},
	{ID: string(commandTierAdvanced), Title: "Advanced Commands"},
}

func init() {
	// Top-level commands (subtrees that self-register to root: hub, mcp, sbom, sign, verify).
	for _, c := range []*cobra.Command{
		serveCmd,
		startCmd,
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

func configureCommandSurface() {
	rootCmd.AddGroup(commandGroups...)

	missing := make([]string, 0)
	for _, c := range rootCmd.Commands() {
		if _, ok := commandTierByName[c.Name()]; ok {
			continue
		}
		missing = append(missing, c.Name())
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		panic(fmt.Sprintf("missing command tier mapping for: %s", strings.Join(missing, ", ")))
	}

	for _, c := range rootCmd.Commands() {
		tier := commandTierByName[c.Name()]
		if c.Annotations == nil {
			c.Annotations = map[string]string{}
		}
		c.Annotations["faramesh-tier"] = string(tier)

		switch tier {
		case commandTierStable:
			c.Hidden = false
			c.GroupID = string(commandTierStable)
		case commandTierAdvanced:
			c.Hidden = false
			c.GroupID = string(commandTierAdvanced)
		default:
			c.Hidden = true
			c.GroupID = ""
		}
	}
}
