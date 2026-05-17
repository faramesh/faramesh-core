package main

import (
	"fmt"
	"os"

	"github.com/faramesh/faramesh-core/internal/runagent"
	"github.com/spf13/cobra"
)

// Hidden entry used only by the apply-generated .faramesh/bin/agent launcher.
var agentExecCmd = &cobra.Command{
	Use:    "__agent-exec",
	Hidden: true,
	Args:   cobra.ArbitraryArgs,
	RunE:   runAgentExec,
}

func runAgentExec(_ *cobra.Command, args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("__agent-exec: missing arguments")
	}
	profile := args[0]
	workspace := args[1]
	proxyPort := args[2]
	rest := args[3:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return fmt.Errorf("no command to execute")
	}
	runagent.ReportFromEnv(profile).Write(os.Stderr)
	return runagent.SandboxExecChild(profile, workspace, proxyPort, rest)
}
