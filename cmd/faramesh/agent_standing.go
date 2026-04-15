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

var standingSocket string
var standingAdminTokenFlag string

var agentStandingGrantCmd = &cobra.Command{
	Use:   "standing-grant",
	Short: "Manage standing approvals (pre-registered DEFER→PERMIT grants)",
}

var standingAddAgent, standingAddSession, standingAddTool, standingAddPolicyVer, standingAddRule, standingAddIssuedBy string
var standingAddTTLSeconds, standingAddMaxUses int

var agentStandingAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Register a standing grant on the daemon (requires admin_token matching daemon config)",
	RunE:  runAgentStandingAdd,
}

var agentStandingRevokeCmd = &cobra.Command{
	Use:   "revoke <grant-id>",
	Short: "Remove a standing grant by id",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentStandingRevoke,
}

var agentStandingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active standing grants",
	Args:  cobra.NoArgs,
	RunE:  runAgentStandingList,
}

func init() {
	agentStandingAddCmd.Flags().StringVar(&standingAddAgent, "agent", "", "agent id (required)")
	agentStandingAddCmd.Flags().StringVar(&standingAddSession, "session", "", "optional session scope")
	agentStandingAddCmd.Flags().StringVar(&standingAddTool, "tool-pattern", "", "tool glob, e.g. pay/* (required)")
	agentStandingAddCmd.Flags().StringVar(&standingAddPolicyVer, "policy-version", "", "optional exact policy version hash")
	agentStandingAddCmd.Flags().StringVar(&standingAddRule, "rule-id", "", "optional policy rule id binding")
	agentStandingAddCmd.Flags().StringVar(&standingAddIssuedBy, "issued-by", "", "operator id (required)")
	agentStandingAddCmd.Flags().IntVar(&standingAddTTLSeconds, "ttl-seconds", 0, "time-to-live (required, max 30d)")
	agentStandingAddCmd.Flags().IntVar(&standingAddMaxUses, "max-uses", 0, "max consumptions (0 = unlimited)")

	agentStandingGrantCmd.PersistentFlags().StringVar(&standingSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	agentStandingGrantCmd.PersistentFlags().StringVar(&standingAdminTokenFlag, "admin-token", "", "must match daemon standing/policy admin secret (or set FARAMESH_STANDING_ADMIN_TOKEN / FARAMESH_POLICY_ADMIN_TOKEN)")

	agentStandingGrantCmd.AddCommand(agentStandingAddCmd, agentStandingRevokeCmd, agentStandingListCmd)
	agentCmd.AddCommand(agentStandingGrantCmd)
}

func runAgentStandingAdd(cmd *cobra.Command, _ []string) error {
	if standingAddAgent == "" || standingAddTool == "" || standingAddIssuedBy == "" || standingAddTTLSeconds <= 0 {
		return fmt.Errorf("--agent, --tool-pattern, --issued-by, and --ttl-seconds (>0) are required")
	}
	resp, err := standingSocketRoundTrip(standingSocket, map[string]any{
		"type":           "standing_grant_add",
		"admin_token":    resolveStandingAdminTokenCLI(),
		"agent_id":       standingAddAgent,
		"session_id":     standingAddSession,
		"tool_pattern":   standingAddTool,
		"policy_version": standingAddPolicyVer,
		"rule_id":        standingAddRule,
		"ttl_seconds":    standingAddTTLSeconds,
		"max_uses":       standingAddMaxUses,
		"issued_by":      standingAddIssuedBy,
	})
	if err != nil {
		return err
	}
	if ok, _ := resp["ok"].(bool); !ok {
		e, _ := resp["error"].(string)
		return fmt.Errorf("%s", e)
	}
	g, _ := resp["grant"].(map[string]any)
	id, _ := g["id"].(string)
	color.New(color.FgGreen, color.Bold).Printf("✓ standing grant %s\n", id)
	return nil
}

func runAgentStandingRevoke(_ *cobra.Command, args []string) error {
	resp, err := standingSocketRoundTrip(standingSocket, map[string]any{
		"type":        "standing_grant_revoke",
		"admin_token": resolveStandingAdminTokenCLI(),
		"grant_id":    args[0],
	})
	if err != nil {
		return err
	}
	if errMsg, _ := resp["error"].(string); errMsg != "" {
		return fmt.Errorf("%s", errMsg)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		return fmt.Errorf("revoke failed or unknown id")
	}
	color.New(color.FgGreen, color.Bold).Println("✓ revoked")
	return nil
}

func runAgentStandingList(_ *cobra.Command, _ []string) error {
	resp, err := standingSocketRoundTrip(standingSocket, map[string]any{
		"type":        "standing_grant_list",
		"admin_token": resolveStandingAdminTokenCLI(),
	})
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Println(string(raw))
	return nil
}

// resolveStandingAdminTokenCLI matches daemon resolution: flag, then env vars.
func resolveStandingAdminTokenCLI() string {
	if strings.TrimSpace(standingAdminTokenFlag) != "" {
		return strings.TrimSpace(standingAdminTokenFlag)
	}
	if v := strings.TrimSpace(os.Getenv("FARAMESH_STANDING_ADMIN_TOKEN")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("FARAMESH_POLICY_ADMIN_TOKEN"))
}

func standingSocketRoundTrip(socket string, payload map[string]any) (map[string]any, error) {
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()
	line, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')
	if _, err := conn.Write(line); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(conn)
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
