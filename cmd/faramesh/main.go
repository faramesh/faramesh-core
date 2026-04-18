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
	Use:          "faramesh",
	Short:        "Faramesh — agent action governance (daemon, policy, run wrapper)",
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
