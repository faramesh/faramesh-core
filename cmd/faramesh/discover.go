package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Statically discover likely governance surfaces in a project",
	Args:  cobra.NoArgs,
	RunE:  runDiscoverE,
}

var (
	discoverJSON bool
	discoverCwd  string
)

func init() {
	discoverCmd.Flags().BoolVar(&discoverJSON, "json", false, "print JSON")
	discoverCmd.Flags().StringVar(&discoverCwd, "cwd", "", "working directory to scan (default: current directory)")
}

func runDiscoverE(_ *cobra.Command, _ []string) error {
	cwd := discoverCwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	report := runtimeenv.DiscoverProject(cwd)
	if discoverJSON {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", body)
		return nil
	}

	fmt.Printf("Root:                 %s\n", report.Root)
	if report.Environment != nil {
		fmt.Printf("Runtime:              %s\n", report.Environment.Runtime)
		fmt.Printf("Framework Hint:       %s\n", report.Environment.Framework)
		fmt.Printf("Agent Harness:        %s\n", report.Environment.AgentHarness)
		fmt.Printf("Trust Level:          %s\n", report.Environment.TrustLevel)
	}
	fmt.Printf("Frameworks:           %s\n", joinOrNone(report.Frameworks))
	fmt.Printf("MCP Config Files:     %s\n", joinOrNone(report.MCPConfigFiles))
	fmt.Printf("Manifest Files:       %s\n", joinOrNone(report.ManifestFiles))
	fmt.Printf("Notebook Files:       %s\n", joinOrNone(report.NotebookFiles))
	fmt.Printf("Network References:   %d\n", len(report.NetworkReferences))
	fmt.Printf("Shell References:     %d\n", len(report.ShellReferences))
	fmt.Printf("Credential References:%d\n", len(report.CredentialReferences))
	fmt.Printf("Candidate Tools:      %d\n", len(report.CandidateTools))
	fmt.Printf("Files Scanned:        %d\n", report.Stats.FilesScanned)

	if len(report.CandidateTools) > 0 {
		fmt.Println()
		fmt.Println("Discovered Tools:")
		for _, tool := range report.CandidateTools {
			fmt.Printf("  - %-20s  surface=%-14s source=%-16s file=%s\n", tool.ID, tool.Surface, tool.Source, tool.File)
		}
	}
	return nil
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}
