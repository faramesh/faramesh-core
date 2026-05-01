package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

type commandTier string

const (
	commandTierCore     commandTier = "core"
	commandTierOperator commandTier = "operator"
	commandTierAdvanced commandTier = "advanced"
	commandTierInternal commandTier = "internal"
)

var commandTierByName = map[string]commandTier{
	"agent":      commandTierOperator,
	"attach":     commandTierOperator,
	"approvals":  commandTierCore,
	"audit":      commandTierCore,
	"auth":       commandTierCore,
	"chaos-test": commandTierInternal,
	"completion": commandTierCore,
	"compliance": commandTierAdvanced,
	"compensate": commandTierInternal,
	"coverage":   commandTierOperator,
	"credential": commandTierCore,
	"delegate":   commandTierAdvanced,
	"demo":       commandTierInternal,
	"detect":     commandTierAdvanced,
	"discover":   commandTierOperator,
	"down":       commandTierCore,
	"explain":    commandTierCore,
	"federation": commandTierAdvanced,
	"fleet":      commandTierAdvanced,
	"gaps":       commandTierOperator,
	"help":       commandTierCore,
	"hub":        commandTierInternal,
	"identity":   commandTierOperator,
	"incident":   commandTierOperator,
	"init":       commandTierAdvanced,
	"mcp":        commandTierOperator,
	"model":      commandTierInternal,
	"offboard":   commandTierOperator,
	"onboard":    commandTierOperator,
	"ops":        commandTierInternal,
	"pack":       commandTierOperator,
	"policy":     commandTierCore,
	"provenance": commandTierOperator,
	"run":        commandTierCore,
	"sbom":       commandTierInternal,
	"schedule":   commandTierAdvanced,
	"serve":      commandTierOperator,
	"session":    commandTierInternal,
	"setup":      commandTierOperator,
	"sign":       commandTierInternal,
	"start":      commandTierOperator,
	"status":     commandTierCore,
	"stop":       commandTierOperator,
	"suggest":    commandTierOperator,
	"up":         commandTierCore,
	"verify":     commandTierInternal,
	"key":        commandTierOperator,
	"wizard":     commandTierCore,
}

var commandGroups = []*cobra.Group{
	{ID: string(commandTierCore), Title: "Core Commands (Start Here)"},
	{ID: string(commandTierOperator), Title: "Operator Commands (Power Path)"},
	{ID: string(commandTierAdvanced), Title: "Advanced Commands (Expert)"},
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
		case commandTierCore:
			c.Hidden = false
			c.GroupID = string(commandTierCore)
		case commandTierOperator:
			c.Hidden = false
			c.GroupID = string(commandTierOperator)
		case commandTierAdvanced:
			c.Hidden = false
			c.GroupID = string(commandTierAdvanced)
		default:
			c.Hidden = true
			c.GroupID = ""
		}
	}
}
