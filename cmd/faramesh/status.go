package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Faramesh daemon status",
	Args:  cobra.NoArgs,
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(_ *cobra.Command, _ []string) error {
	raw, err := daemonGet("/api/v1/status")
	if err != nil {
		return err
	}

	var resp struct {
		Running        bool   `json:"running"`
		PolicyLoaded   bool   `json:"policy_loaded"`
		PolicyVersion  string `json:"policy_version"`
		DPRHealthy     bool   `json:"dpr_healthy"`
		ActiveSessions int    `json:"active_sessions"`
		TrustLevel     string `json:"trust_level"`
		UptimeSeconds  int64  `json:"uptime_seconds"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode daemon response: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	bold.Fprintln(os.Stdout, "Faramesh Daemon Status")
	fmt.Println()

	check := func(ok bool, label string) {
		if ok {
			green.Fprintf(os.Stdout, "  ✓ %s\n", label)
		} else {
			red.Fprintf(os.Stdout, "  ✗ %s\n", label)
		}
	}

	check(resp.Running, "Daemon running")
	if resp.PolicyVersion != "" {
		check(resp.PolicyLoaded, fmt.Sprintf("Policy loaded (%s)", resp.PolicyVersion))
	} else {
		check(resp.PolicyLoaded, "Policy loaded")
	}
	check(resp.DPRHealthy, "DPR store healthy")

	fmt.Println()
	fmt.Fprintf(os.Stdout, "  Active sessions:  %d\n", resp.ActiveSessions)
	bold.Fprintf(os.Stdout, "  Trust level:      %s\n", resp.TrustLevel)
	fmt.Fprintf(os.Stdout, "  Uptime:           %s\n",
		(time.Duration(resp.UptimeSeconds) * time.Second).Truncate(time.Second))
	fmt.Println()

	return nil
}
