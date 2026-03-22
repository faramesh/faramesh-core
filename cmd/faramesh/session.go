package main

import (
	"net/url"

	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage agent governance sessions",
	Long: `Create, inspect, and manage governance sessions for AI agents.
Sessions track budgets, counters, purposes, and lifecycle state.`,
}

// ── session open ────────────────────────────────────────────────────────────

var (
	sessionOpenBudget int
	sessionOpenTTL    string
)

var sessionOpenCmd = &cobra.Command{
	Use:   "open <agent-id>",
	Short: "Open a governance session for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"agent_id": args[0]}
		if cmd.Flags().Changed("budget") {
			body["budget"] = sessionOpenBudget
		}
		if cmd.Flags().Changed("ttl") {
			body["ttl"] = sessionOpenTTL
		}
		data, err := daemonPost("/api/v1/session/open", body)
		if err != nil {
			return err
		}
		printHeader("Session Opened")
		printJSON(data)
		return nil
	},
}

// ── session close ───────────────────────────────────────────────────────────

var sessionCloseCmd = &cobra.Command{
	Use:   "close <agent-id>",
	Short: "Close an active governance session",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		body := map[string]any{"agent_id": args[0]}
		data, err := daemonPost("/api/v1/session/close", body)
		if err != nil {
			return err
		}
		printHeader("Session Closed")
		printJSON(data)
		return nil
	},
}

// ── session list ────────────────────────────────────────────────────────────

var sessionListAgent string

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List governance sessions",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		path := "/api/v1/session/list"
		if cmd.Flags().Changed("agent") {
			path += "?" + url.Values{"agent": {sessionListAgent}}.Encode()
		}
		data, err := daemonGet(path)
		if err != nil {
			return err
		}
		printHeader("Sessions")
		printJSON(data)
		return nil
	},
}

// ── session budget ──────────────────────────────────────────────────────────

var sessionBudgetSet int

var sessionBudgetCmd = &cobra.Command{
	Use:   "budget <agent-id>",
	Short: "View or set the budget for a session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentID := args[0]
		if cmd.Flags().Changed("set") {
			body := map[string]any{
				"agent_id": agentID,
				"budget":   sessionBudgetSet,
			}
			data, err := daemonPost("/api/v1/session/budget", body)
			if err != nil {
				return err
			}
			printHeader("Budget Updated")
			printJSON(data)
			return nil
		}
		data, err := daemonGet("/api/v1/session/budget?" + url.Values{"agent": {agentID}}.Encode())
		if err != nil {
			return err
		}
		printHeader("Session Budget")
		printJSON(data)
		return nil
	},
}

// ── session reset ───────────────────────────────────────────────────────────

var sessionResetCounter string

var sessionResetCmd = &cobra.Command{
	Use:   "reset <agent-id>",
	Short: "Reset session counters for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"agent_id": args[0]}
		if cmd.Flags().Changed("counter") {
			body["counter"] = sessionResetCounter
		}
		data, err := daemonPost("/api/v1/session/reset", body)
		if err != nil {
			return err
		}
		printHeader("Session Reset")
		printJSON(data)
		return nil
	},
}

// ── session inspect ─────────────────────────────────────────────────────────

var sessionInspectCmd = &cobra.Command{
	Use:   "inspect <agent-id>",
	Short: "Inspect the full state of a governance session",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		data, err := daemonGet("/api/v1/session/inspect/" + url.PathEscape(args[0]))
		if err != nil {
			return err
		}
		printHeader("Session Details")
		printJSON(data)
		return nil
	},
}

// ── session purpose ─────────────────────────────────────────────────────────

var sessionPurposeCmd = &cobra.Command{
	Use:   "purpose",
	Short: "Manage session purpose declarations",
}

var sessionPurposeDeclareCmd = &cobra.Command{
	Use:   "declare <agent-id> <purpose>",
	Short: "Declare a purpose for the session",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		body := map[string]any{
			"agent_id": args[0],
			"purpose":  args[1],
		}
		data, err := daemonPost("/api/v1/session/purpose/declare", body)
		if err != nil {
			return err
		}
		printHeader("Purpose Declared")
		printJSON(data)
		return nil
	},
}

var sessionPurposeListCmd = &cobra.Command{
	Use:   "list <agent-id>",
	Short: "List purposes declared for a session",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		data, err := daemonGet("/api/v1/session/purpose/" + url.PathEscape(args[0]))
		if err != nil {
			return err
		}
		printHeader("Session Purposes")
		printJSON(data)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sessionCmd)

	sessionOpenCmd.Flags().IntVar(&sessionOpenBudget, "budget", 0, "maximum number of tool calls allowed")
	sessionOpenCmd.Flags().StringVar(&sessionOpenTTL, "ttl", "", "session time-to-live (e.g. 30m, 2h)")

	sessionListCmd.Flags().StringVar(&sessionListAgent, "agent", "", "filter sessions by agent ID")

	sessionBudgetCmd.Flags().IntVar(&sessionBudgetSet, "set", 0, "set the budget to this value")

	sessionResetCmd.Flags().StringVar(&sessionResetCounter, "counter", "", "specific counter to reset (default: all)")

	sessionPurposeCmd.AddCommand(sessionPurposeDeclareCmd)
	sessionPurposeCmd.AddCommand(sessionPurposeListCmd)

	sessionCmd.AddCommand(sessionOpenCmd)
	sessionCmd.AddCommand(sessionCloseCmd)
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionBudgetCmd)
	sessionCmd.AddCommand(sessionResetCmd)
	sessionCmd.AddCommand(sessionInspectCmd)
	sessionCmd.AddCommand(sessionPurposeCmd)
}
