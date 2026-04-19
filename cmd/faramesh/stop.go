package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Gracefully stop the Faramesh runtime",
	Args:  cobra.NoArgs,
	RunE:  runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)
}

func runStop(_ *cobra.Command, _ []string) error {
	raw, err := daemonSocketRequest(map[string]any{"type": "shutdown"})
	if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
		raw, err = daemonPost("/api/v1/shutdown", nil)
	}
	if err != nil {
		return fmt.Errorf("stop runtime: %w", err)
	}

	var resp struct {
		Message string `json:"message"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &resp); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	color.New(color.Bold, color.FgGreen).Fprintln(os.Stdout, "✓ Runtime shutdown initiated")
	if resp.Message != "" {
		fmt.Fprintf(os.Stdout, "  %s\n", resp.Message)
	}
	return nil
}
