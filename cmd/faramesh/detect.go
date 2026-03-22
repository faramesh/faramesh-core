package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
)

var detectEnvCmd = &cobra.Command{
	Use:   "detect",
	Short: "Print detected runtime / framework / harness (machine or human readable)",
	Args:  cobra.NoArgs,
	RunE:  runDetectEnvE,
}

var (
	detectJSON bool
	detectCwd  string
)

func init() {
	detectEnvCmd.Flags().BoolVar(&detectJSON, "json", false, "print JSON")
	detectEnvCmd.Flags().StringVar(&detectCwd, "cwd", "", "working directory to scan (default: current directory)")
}

func runDetectEnvE(_ *cobra.Command, _ []string) error {
	cwd := detectCwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	det := runtimeenv.DetectEnvironment(cwd)
	if detectJSON {
		b, err := det.ToJSON()
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", b)
		return nil
	}
	fmt.Printf("Runtime:       %s\n", det.Runtime)
	fmt.Printf("Framework:     %s\n", det.Framework)
	fmt.Printf("Agent harness: %s\n", det.AgentHarness)
	fmt.Printf("IDE hint:      %s\n", det.IDE)
	fmt.Printf("Adapter level: %d\n", det.AdapterLevel)
	fmt.Printf("Trust level:   %s\n", det.TrustLevel)
	fmt.Printf("GoOS:          %s\n", det.GoOS)
	return nil
}
