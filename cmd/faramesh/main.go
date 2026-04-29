package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Set via -ldflags at release builds.
var (
	version = "dev"
	commit  = ""
)

var rootCmd = &cobra.Command{
	Use:   "faramesh",
	Short: "Faramesh — govern AI agent actions with policy and approvals",
	Long: `Faramesh is the governance control surface for AI agent actions.

Start with the default workflow:
  faramesh wizard first-run
  faramesh run --broker -- python your_agent.py`,
	Example: `  faramesh wizard first-run
  faramesh up --policy policy.yaml
  faramesh approvals
  faramesh explain <action-id>`,
	SilenceUsage: true,
	Version:      version,
}

func main() {
	if commit != "" {
		rootCmd.Version = fmt.Sprintf("%s (%s)", version, commit)
	}
	configureCommandSurface()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")
}
