package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance/initwriter"
	"github.com/spf13/cobra"
)

var (
	initDir             string
	initOffline         bool
	initNonInteractive  bool
	initYAML            bool
	initJSON            bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate governance.fms for this stack",
	Long:  "Detects framework and tools, writes governance.fms once per stack. Does not start the daemon.",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().StringVar(&initDir, "dir", ".", "stack directory")
	initCmd.Flags().BoolVar(&initOffline, "offline", false, "omit registry import line; no network")
	initCmd.Flags().BoolVar(&initNonInteractive, "non-interactive", false, "no prompts; unknown framework writes TODO import")
	initCmd.Flags().BoolVar(&initYAML, "yaml", false, "write governance.fms.yaml")
	initCmd.Flags().BoolVar(&initJSON, "json", false, "write governance.fms.json")
}

func runInit(_ *cobra.Command, _ []string) error {
	stackDir, err := filepath.Abs(initDir)
	if err != nil {
		return err
	}

	framework, ambiguous := initwriter.DetectFramework(stackDir)
	if framework == "" && len(ambiguous) > 0 && !initNonInteractive {
		fmt.Println("Multiple frameworks detected:")
		for i, f := range ambiguous {
			fmt.Printf("  %d) %s\n", i+1, f)
		}
		fmt.Print("Select framework number: ")
		var choice int
		if _, err := fmt.Scanln(&choice); err != nil || choice < 1 || choice > len(ambiguous) {
			return fmt.Errorf("invalid framework selection")
		}
		framework = ambiguous[choice-1]
	}
	if framework == "" && !initNonInteractive && !initOffline {
		framework, err = promptFramework()
		if err != nil {
			return err
		}
	}

	res, err := initwriter.Run(initwriter.Options{
		Dir:               stackDir,
		Offline:           initOffline,
		NonInteractive:    initNonInteractive,
		FormatYAML:        initYAML,
		FormatJSON:        initJSON,
		SelectedFramework: framework,
	})
	if err != nil {
		return err
	}
	if res.AlreadyExists {
		fmt.Fprintln(os.Stderr, "governance.fms already exists. To reinitialize, delete it first.")
		return fmt.Errorf("governance file already exists")
	}

	printInitSuccess(res)
	return nil
}

func promptFramework() (string, error) {
	choices := []string{
		"langgraph", "langchain", "crewai", "ag2", "google-adk", "openai-agents",
		"anthropic-sdk", "strands", "bedrock", "mcp", "deep-agents", "other",
	}
	fmt.Println("Framework not detected automatically.")
	fmt.Println("Which framework are you using?")
	for i, c := range choices {
		fmt.Printf("  %d) %s\n", i+1, c)
	}
	fmt.Print("Select number: ")
	var n int
	if _, err := fmt.Scanln(&n); err != nil || n < 1 || n > len(choices) {
		return "", fmt.Errorf("invalid selection")
	}
	sel := choices[n-1]
	if sel == "other" {
		fmt.Print("Enter framework id: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		sel = strings.TrimSpace(line)
	}
	fmt.Printf("Selected: %s\n\n", sel)
	return sel, nil
}

func printInitSuccess(res *initwriter.Result) {
	fw := res.Framework
	if res.Framework == "unknown" {
		// non-interactive unknown path
	}
	if len(res.Tools) > 0 {
		names := make([]string, len(res.Tools))
		for i, t := range res.Tools {
			names[i] = t.Name
		}
		fmt.Printf("✓ Framework detected: %s\n", fw)
		fmt.Printf("✓ Tools discovered: %d (%s)\n", len(names), strings.Join(names, ","))
		fmt.Println("✓ governance.fms written")
	} else if res.Framework != "" && res.Framework != "unknown" {
		fmt.Printf("✓ Framework detected: %s\n\n", fw)
		fmt.Println("No tools discovered automatically.")
		fmt.Println("Add rules to governance.fms manually.")
		fmt.Println("See: https://docs.faramesh.dev/fpl")
		fmt.Println()
		fmt.Println("✓ governance.fms written")
	} else {
		fmt.Println("✓ governance.fms written")
	}
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  Run your agent with governance:")
	fmt.Println("    faramesh dev")
	fmt.Println("  Review what your agent is doing:")
	fmt.Println("    faramesh approvals list")
	fmt.Println("  When ready for full enforcement:")
	fmt.Println("    faramesh apply")
	fmt.Println()
	fmt.Println("Docs: https://docs.faramesh.dev/init")
}
