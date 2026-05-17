package main

import (
	"os/exec"

	"github.com/spf13/cobra"
)

type commandTier string

const (
	commandTierCore     commandTier = "core"
	commandTierOperator commandTier = "operator"
	commandTierInternal commandTier = "internal"
)

var commandTierByName = map[string]commandTier{
	"init":       commandTierCore,
	"check":      commandTierCore,
	"plan":       commandTierCore,
	"apply":      commandTierCore,
	"status":     commandTierCore,
	"destroy":    commandTierCore,
	"test":       commandTierCore,
	"explain":    commandTierCore,
	"rollback":   commandTierCore,
	"dev":        commandTierCore,
	"run":        commandTierCore,
	"approvals":  commandTierCore,
	"audit":      commandTierCore,
	"credential": commandTierCore,
	"agent":      commandTierOperator,
	"bundle":     commandTierOperator,
	"registry":   commandTierCore,
	"auth":       commandTierCore,
	"completion": commandTierCore,
	"help":       commandTierCore,
	"serve":      commandTierInternal,
}

var commandGroups = []*cobra.Group{
	{ID: string(commandTierCore), Title: "Core Commands"},
	{ID: string(commandTierOperator), Title: "Operator Commands"},
}

func init() {
	for _, c := range []*cobra.Command{
		initCmd,
		checkCmd,
		planCmd,
		applyCmd,
		statusCmd,
		destroyCmd,
		testCmd,
		explainCmd,
		rollbackCmd,
		devCmd,
		runCmd,
		sandboxExecCmd,
		approvalsCmd,
		auditCmd,
		credentialCmd,
		agentCmd,
		bundleCmd,
		registryCmd,
		authCmd,
		serveCmd,
	} {
		rootCmd.AddCommand(c)
	}
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func configureCommandSurface() {
	rootCmd.AddGroup(commandGroups...)

	for _, c := range rootCmd.Commands() {
		tier, ok := commandTierByName[c.Name()]
		if !ok {
			tier = commandTierInternal
		}
		if c.Annotations == nil {
			c.Annotations = map[string]string{}
		}
		c.Annotations["faramesh-tier"] = string(tier)

		switch tier {
		case commandTierCore, commandTierOperator:
			c.Hidden = false
			c.GroupID = string(tier)
		default:
			c.Hidden = true
			c.GroupID = ""
		}
	}
}
