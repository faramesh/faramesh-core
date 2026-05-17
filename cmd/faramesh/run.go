package main

import (
	"fmt"
	"os"

	"github.com/faramesh/faramesh-core/internal/runagent"
	"github.com/spf13/cobra"
)

var (
	runEnforce  string
	runBroker   bool
	runAgentID  string
	runWorkspace string
	runProxyPort int
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run an agent command with Faramesh OS enforcement and SDK autoload",
	Long: `Wraps an agent process with credential broker stripping, FARAMESH_AUTOLOAD, and
OS-tier sandboxing (Linux: seccomp+Landlock; macOS: Seatbelt via sandbox-exec).

  faramesh run --broker --agent-id my-agent -- python agent.py
  faramesh run --enforce full --broker -- ./my-binary`,
	Args: cobra.ArbitraryArgs,
	RunE: runRun,
}

var sandboxExecCmd = &cobra.Command{
	Use:    "__sandbox-exec",
	Hidden: true,
	Args:   cobra.ArbitraryArgs,
	RunE:   runSandboxExec,
}

func init() {
	runCmd.Flags().StringVar(&runEnforce, "enforce", "auto", "enforcement profile: auto|full|minimal|off")
	runCmd.Flags().BoolVar(&runBroker, "broker", false, "strip ambient API keys from child environment")
	runCmd.Flags().StringVar(&runAgentID, "agent-id", "", "agent id for FARAMESH_AGENT_ID")
	runCmd.Flags().StringVar(&runWorkspace, "workspace", "", "workspace path for filesystem sandbox (default: cwd)")
	runCmd.Flags().IntVar(&runProxyPort, "proxy-port", 18443, "local proxy port for macOS Seatbelt network allowlist")
}

func runRun(_ *cobra.Command, args []string) error {
	argv := args
	for i, a := range args {
		if a == "--" {
			argv = args[i+1:]
			break
		}
	}
	if len(argv) == 0 {
		return fmt.Errorf("pass agent command after --")
	}
	return runagent.Launch(argv, runagent.Options{
		Profile:      runEnforce,
		Broker:       runBroker,
		AgentID:      runAgentID,
		Workspace:    runWorkspace,
		ProxyPort:    runProxyPort,
		ReportWriter: os.Stderr,
	})
}

func runSandboxExec(_ *cobra.Command, args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("__sandbox-exec: missing arguments")
	}
	profile := args[0]
	workspace := args[1]
	proxyPort := args[2]
	rest := args[3:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	return runagent.SandboxExecChild(profile, workspace, proxyPort, rest)
}
