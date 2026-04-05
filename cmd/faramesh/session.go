package main

import (
	"encoding/json"
	"net/url"

	"github.com/spf13/cobra"
)

func sessionSocketRequest(op string, payload map[string]any) (json.RawMessage, error) {
	req := map[string]any{"type": "session", "op": op}
	for k, v := range payload {
		req[k] = v
	}
	return daemonSocketRequest(req)
}

func sessionSocketRequestWithHTTPFallback(op string, payload map[string]any, httpMethod, httpPath string) (json.RawMessage, error) {
	data, err := sessionSocketRequest(op, payload)
	if err == nil {
		return data, nil
	}
	if !daemonHTTPFallback {
		return nil, err
	}
	if httpMethod == "GET" {
		return daemonGet(httpPath)
	}
	return daemonPost(httpPath, payload)
}

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
		data, err := sessionSocketRequestWithHTTPFallback("open", body, "POST", "/api/v1/session/open")
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
		data, err := sessionSocketRequestWithHTTPFallback("close", body, "POST", "/api/v1/session/close")
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
		payload := map[string]any{}
		if cmd.Flags().Changed("agent") {
			payload["agent_id"] = sessionListAgent
			path += "?" + url.Values{"agent": {sessionListAgent}}.Encode()
		}
		data, err := sessionSocketRequestWithHTTPFallback("list", payload, "GET", path)
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
			data, err := sessionSocketRequestWithHTTPFallback("budget_set", body, "POST", "/api/v1/session/budget")
			if err != nil {
				return err
			}
			printHeader("Budget Updated")
			printJSON(data)
			return nil
		}
		data, err := sessionSocketRequestWithHTTPFallback("budget_get", map[string]any{"agent_id": agentID}, "GET", "/api/v1/session/budget?"+url.Values{"agent": {agentID}}.Encode())
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
		data, err := sessionSocketRequestWithHTTPFallback("reset", body, "POST", "/api/v1/session/reset")
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
		httpPath := "/api/v1/session/inspect/" + url.PathEscape(args[0])
		data, err := sessionSocketRequestWithHTTPFallback("inspect", map[string]any{"agent_id": args[0]}, "GET", httpPath)
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
		data, err := sessionSocketRequestWithHTTPFallback("purpose_declare", body, "POST", "/api/v1/session/purpose/declare")
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
		httpPath := "/api/v1/session/purpose/" + url.PathEscape(args[0])
		data, err := sessionSocketRequestWithHTTPFallback("purpose_list", map[string]any{"agent_id": args[0]}, "GET", httpPath)
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
