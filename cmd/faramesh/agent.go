package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Fleet management: approve/deny pending actions, kill switch",
}

var agentApproveCmd = &cobra.Command{
	Use:   "approve <defer-token>",
	Short: "Approve a pending DEFER action",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentApprove,
}

var agentDenyCmd = &cobra.Command{
	Use:   "deny <defer-token>",
	Short: "Deny a pending DEFER action",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentDeny,
}

var agentKillCmd = &cobra.Command{
	Use:   "kill <agent-id>",
	Short: "Activate kill switch for an agent — all subsequent calls will DENY",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentKill,
}

var agentApproveSocket string

var agentUnkillCmd = &cobra.Command{
	Use:   "unkill <agent-id>",
	Short: "Deactivate kill switch for an agent — resume normal evaluation",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := daemonSocketRequest(map[string]any{
			"type":  "agent",
			"op":    "unkill",
			"agent": args[0],
		})
		if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonPost("/api/v1/agent/unkill", map[string]string{"agent_id": args[0]})
		}
		if err != nil {
			return err
		}
		printResponse("Agent Unkill", raw)
		return nil
	},
}

var agentKilledCmd = &cobra.Command{
	Use:   "killed",
	Short: "List all agents with an active kill switch",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		raw, err := daemonSocketRequest(map[string]any{
			"type": "agent",
			"op":   "killed",
		})
		if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonGet("/api/v1/agent/killed")
		}
		if err != nil {
			return err
		}
		printResponse("Killed Agents", raw)
		return nil
	},
}

var agentPendingAgent string

var agentPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending DEFER actions (optionally filtered by agent)",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		q := map[string]string{}
		socketReq := map[string]any{
			"type": "agent",
			"op":   "pending",
		}
		if agentPendingAgent != "" {
			q["agent"] = agentPendingAgent
			socketReq["agent"] = agentPendingAgent
		}
		raw, err := daemonSocketRequest(socketReq)
		if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonGetWithQuery("/api/v1/agent/pending", q)
		}
		if err != nil {
			return err
		}
		printResponse("Pending Actions", raw)
		return nil
	},
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all known agents",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		raw, err := daemonSocketRequest(map[string]any{
			"type": "agent",
			"op":   "list",
		})
		if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonGet("/api/v1/agent/list")
		}
		if err != nil {
			return err
		}
		printResponse("Agents", raw)
		return nil
	},
}

var agentInspectCmd = &cobra.Command{
	Use:   "inspect <agent-id>",
	Short: "Show detailed state for a single agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := daemonSocketRequest(map[string]any{
			"type": "agent",
			"op":   "inspect",
			"id":   args[0],
		})
		if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonGetWithQuery("/api/v1/agent/inspect", map[string]string{"id": args[0]})
		}
		if err != nil {
			return err
		}
		printResponse("Agent Detail", raw)
		return nil
	},
}

var agentHistoryWindow string

var agentHistoryCmd = &cobra.Command{
	Use:   "history <agent-id>",
	Short: "Show evaluation history for an agent",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		q := map[string]string{"id": args[0]}
		socketReq := map[string]any{
			"type": "agent",
			"op":   "history",
			"id":   args[0],
		}
		if agentHistoryWindow != "" {
			q["window"] = agentHistoryWindow
			socketReq["window"] = agentHistoryWindow
		}
		raw, err := daemonSocketRequest(socketReq)
		if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonGetWithQuery("/api/v1/agent/history", q)
		}
		if err != nil {
			return err
		}
		printResponse("Agent History", raw)
		return nil
	},
}

func init() {
	agentApproveCmd.Flags().StringVar(&agentApproveSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	agentDenyCmd.Flags().StringVar(&agentApproveSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	agentKillCmd.Flags().StringVar(&agentApproveSocket, "socket", sdk.SocketPath, "daemon Unix socket path")

	agentPendingCmd.Flags().StringVar(&agentPendingAgent, "agent", "", "filter by agent ID")
	agentHistoryCmd.Flags().StringVar(&agentHistoryWindow, "window", "", "time window (e.g. 1h, 24h)")

	agentCmd.AddCommand(agentApproveCmd)
	agentCmd.AddCommand(agentDenyCmd)
	agentCmd.AddCommand(agentKillCmd)
	agentCmd.AddCommand(agentUnkillCmd)
	agentCmd.AddCommand(agentKilledCmd)
	agentCmd.AddCommand(agentPendingCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentInspectCmd)
	agentCmd.AddCommand(agentHistoryCmd)
}

func runAgentApprove(cmd *cobra.Command, args []string) error {
	return sendApproval(args[0], true, "")
}

func runAgentDeny(cmd *cobra.Command, args []string) error {
	return sendApproval(args[0], false, "")
}

func sendApproval(token string, approved bool, reason string) error {
	socketPath := resolveAgentControlSocket()

	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()

	req, _ := json.Marshal(map[string]any{
		"type":        "approve_defer",
		"defer_token": token,
		"approved":    approved,
		"reason":      reason,
	})
	req = append(req, '\n')
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	dec := json.NewDecoder(conn)
	var resp map[string]any
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if ok, _ := resp["ok"].(bool); ok {
		word := "approved"
		if !approved {
			word = "denied"
		}
		color.New(color.FgGreen, color.Bold).Printf("✓ ")
		fmt.Printf("DEFER token %s %s\n", token, word)
	} else {
		errMsg, _ := resp["error"].(string)
		color.New(color.FgRed, color.Bold).Printf("✗ ")
		fmt.Printf("Failed: %s\n", errMsg)
	}
	return nil
}

func runAgentKill(cmd *cobra.Command, args []string) error {
	agentID := args[0]
	socketPath := resolveAgentControlSocket()
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()

	req, _ := json.Marshal(map[string]any{
		"type":     "kill",
		"agent_id": agentID,
	})
	req = append(req, '\n')
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	dec := json.NewDecoder(conn)
	var resp map[string]any
	if err := dec.Decode(&resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if ok, _ := resp["ok"].(bool); ok {
		color.New(color.FgRed, color.Bold).Printf("⚡ ")
		fmt.Printf("Kill switch activated for agent: %s\n", agentID)
		fmt.Println("All subsequent calls from this agent will be DENIED.")
	}
	return nil
}

func resolveAgentControlSocket() string {
	socketPath := strings.TrimSpace(agentApproveSocket)
	if socketPath == "" || socketPath == sdk.SocketPath {
		return resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
	}
	return socketPath
}
