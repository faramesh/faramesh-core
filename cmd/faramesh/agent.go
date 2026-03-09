package main

import (
	"encoding/json"
	"fmt"
	"net"
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

func init() {
	agentApproveCmd.Flags().StringVar(&agentApproveSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	agentDenyCmd.Flags().StringVar(&agentApproveSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	agentKillCmd.Flags().StringVar(&agentApproveSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	agentCmd.AddCommand(agentApproveCmd)
	agentCmd.AddCommand(agentDenyCmd)
	agentCmd.AddCommand(agentKillCmd)
}

func runAgentApprove(cmd *cobra.Command, args []string) error {
	return sendApproval(args[0], true, "")
}

func runAgentDeny(cmd *cobra.Command, args []string) error {
	return sendApproval(args[0], false, "")
}

func sendApproval(token string, approved bool, reason string) error {
	conn, err := net.DialTimeout("unix", agentApproveSocket, 3*time.Second)
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
	conn, err := net.DialTimeout("unix", agentApproveSocket, 3*time.Second)
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
