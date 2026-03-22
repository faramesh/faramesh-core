package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type delegationEntry struct {
	Token     string `json:"token"`
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	Scope     string `json:"scope"`
	ExpiresAt string `json:"expires_at"`
	Ceiling   string `json:"ceiling"`
	Active    bool   `json:"active"`
	CreatedAt string `json:"created_at"`
	Depth     int    `json:"chain_depth"`
}

var delegateCmd = &cobra.Command{
	Use:   "delegate",
	Short: "Manage agent-to-agent delegation chains",
	Long: `Create, inspect, verify, and revoke delegation tokens that allow one agent
to act on behalf of another within a governed chain of trust.`,
}

var delegateGrantCmd = &cobra.Command{
	Use:   "grant <from-agent> <to-agent>",
	Short: "Grant delegation from one agent to another",
	Args:  cobra.ExactArgs(2),
	RunE:  runDelegateGrant,
}

var delegateListCmd = &cobra.Command{
	Use:   "list <agent-id>",
	Short: "List delegations for an agent",
	Args:  cobra.ExactArgs(1),
	RunE:  runDelegateList,
}

var delegateRevokeCmd = &cobra.Command{
	Use:   "revoke <from-agent> <to-agent>",
	Short: "Revoke delegation between two agents",
	Args:  cobra.ExactArgs(2),
	RunE:  runDelegateRevoke,
}

var delegateInspectCmd = &cobra.Command{
	Use:   "inspect <delegation-token>",
	Short: "Inspect a delegation token's metadata",
	Args:  cobra.ExactArgs(1),
	RunE:  runDelegateInspect,
}

var delegateVerifyCmd = &cobra.Command{
	Use:   "verify <delegation-token>",
	Short: "Verify whether a delegation token is currently valid",
	Args:  cobra.ExactArgs(1),
	RunE:  runDelegateVerify,
}

var delegateChainCmd = &cobra.Command{
	Use:   "chain <agent-id>",
	Short: "Show the full delegation chain for an agent",
	Args:  cobra.ExactArgs(1),
	RunE:  runDelegateChain,
}

var (
	delegateGrantScope   string
	delegateGrantTTL     string
	delegateGrantCeiling string
)

func init() {
	delegateGrantCmd.Flags().StringVar(&delegateGrantScope, "scope", "*", "delegation scope (tool pattern)")
	delegateGrantCmd.Flags().StringVar(&delegateGrantTTL, "ttl", "1h", "delegation time-to-live")
	delegateGrantCmd.Flags().StringVar(&delegateGrantCeiling, "ceiling", "", "spending or action ceiling")

	delegateCmd.AddCommand(
		delegateGrantCmd,
		delegateListCmd,
		delegateRevokeCmd,
		delegateInspectCmd,
		delegateVerifyCmd,
		delegateChainCmd,
	)
	rootCmd.AddCommand(delegateCmd)
}

func runDelegateGrant(_ *cobra.Command, args []string) error {
	req := map[string]string{
		"from_agent": args[0],
		"to_agent":   args[1],
		"scope":      delegateGrantScope,
		"ttl":        delegateGrantTTL,
	}
	if delegateGrantCeiling != "" {
		req["ceiling"] = delegateGrantCeiling
	}

	raw, err := daemonPost("/api/v1/delegate/grant", req)
	if err != nil {
		return err
	}

	var resp struct {
		Token     string `json:"token"`
		FromAgent string `json:"from_agent"`
		ToAgent   string `json:"to_agent"`
		Scope     string `json:"scope"`
		ExpiresAt string `json:"expires_at"`
		Ceiling   string `json:"ceiling"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	bold := color.New(color.Bold)
	color.New(color.FgGreen, color.Bold).Fprintln(os.Stdout, "✓ Delegation granted")
	fmt.Println()
	bold.Fprintf(os.Stdout, "  Token:      ")
	fmt.Fprintln(os.Stdout, resp.Token)
	fmt.Fprintf(os.Stdout, "  From:       %s\n", resp.FromAgent)
	fmt.Fprintf(os.Stdout, "  To:         %s\n", resp.ToAgent)
	fmt.Fprintf(os.Stdout, "  Scope:      %s\n", resp.Scope)
	fmt.Fprintf(os.Stdout, "  Expires:    %s\n", resp.ExpiresAt)
	if resp.Ceiling != "" {
		fmt.Fprintf(os.Stdout, "  Ceiling:    %s\n", resp.Ceiling)
	}
	fmt.Println()

	return nil
}

func runDelegateList(_ *cobra.Command, args []string) error {
	q := url.Values{"agent_id": {args[0]}}

	raw, err := daemonGet("/api/v1/delegate/list?" + q.Encode())
	if err != nil {
		return err
	}

	var resp struct {
		Delegations []delegationEntry `json:"delegations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	color.New(color.Bold).Fprintf(os.Stdout, "Delegations for %s\n\n", args[0])

	if len(resp.Delegations) == 0 {
		fmt.Fprintln(os.Stdout, "  No delegations found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  TOKEN\tFROM\tTO\tSCOPE\tEXPIRES\tACTIVE")
	for _, d := range resp.Delegations {
		active := "yes"
		if !d.Active {
			active = "no"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			truncateToken(d.Token), d.FromAgent, d.ToAgent, d.Scope, d.ExpiresAt, active)
	}
	w.Flush()
	fmt.Println()

	return nil
}

func runDelegateRevoke(_ *cobra.Command, args []string) error {
	req := map[string]string{
		"from_agent": args[0],
		"to_agent":   args[1],
	}

	raw, err := daemonPost("/api/v1/delegate/revoke", req)
	if err != nil {
		return err
	}

	var resp struct {
		Revoked bool   `json:"revoked"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if resp.Revoked {
		color.New(color.FgGreen).Fprintf(os.Stdout, "✓ Delegation from %s to %s revoked\n", args[0], args[1])
	} else {
		color.New(color.FgYellow).Fprintf(os.Stdout, "⚠ %s\n", resp.Message)
	}
	return nil
}

func runDelegateInspect(_ *cobra.Command, args []string) error {
	q := url.Values{"token": {args[0]}}

	raw, err := daemonGet("/api/v1/delegate/inspect?" + q.Encode())
	if err != nil {
		return err
	}

	var resp delegationEntry
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	color.New(color.Bold).Fprintln(os.Stdout, "Delegation Token Details")
	fmt.Println()
	fmt.Fprintf(os.Stdout, "  Token:       %s\n", resp.Token)
	fmt.Fprintf(os.Stdout, "  From:        %s\n", resp.FromAgent)
	fmt.Fprintf(os.Stdout, "  To:          %s\n", resp.ToAgent)
	fmt.Fprintf(os.Stdout, "  Scope:       %s\n", resp.Scope)
	fmt.Fprintf(os.Stdout, "  Expires:     %s\n", resp.ExpiresAt)
	if resp.Ceiling != "" {
		fmt.Fprintf(os.Stdout, "  Ceiling:     %s\n", resp.Ceiling)
	}
	active := "yes"
	if !resp.Active {
		active = "no"
	}
	fmt.Fprintf(os.Stdout, "  Active:      %s\n", active)
	fmt.Fprintf(os.Stdout, "  Created:     %s\n", resp.CreatedAt)
	fmt.Fprintf(os.Stdout, "  Chain depth: %d\n", resp.Depth)
	fmt.Println()

	return nil
}

func runDelegateVerify(_ *cobra.Command, args []string) error {
	req := map[string]string{"token": args[0]}

	raw, err := daemonPost("/api/v1/delegate/verify", req)
	if err != nil {
		return err
	}

	var resp struct {
		Valid      bool   `json:"valid"`
		Reason     string `json:"reason"`
		Scope      string `json:"scope"`
		ExpiresAt  string `json:"expires_at"`
		ChainDepth int    `json:"chain_depth"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if resp.Valid {
		color.New(color.FgGreen, color.Bold).Fprintln(os.Stdout, "✓ Token is valid")
		fmt.Fprintf(os.Stdout, "  Scope:       %s\n", resp.Scope)
		fmt.Fprintf(os.Stdout, "  Expires:     %s\n", resp.ExpiresAt)
		fmt.Fprintf(os.Stdout, "  Chain depth: %d\n", resp.ChainDepth)
	} else {
		color.New(color.FgRed, color.Bold).Fprintln(os.Stdout, "✗ Token is invalid")
		fmt.Fprintf(os.Stdout, "  Reason: %s\n", resp.Reason)
	}
	fmt.Println()

	return nil
}

func runDelegateChain(_ *cobra.Command, args []string) error {
	q := url.Values{"agent_id": {args[0]}}

	raw, err := daemonGet("/api/v1/delegate/chain?" + q.Encode())
	if err != nil {
		return err
	}

	var resp struct {
		AgentID string `json:"agent_id"`
		Chain   []struct {
			FromAgent string `json:"from_agent"`
			ToAgent   string `json:"to_agent"`
			Scope     string `json:"scope"`
			ExpiresAt string `json:"expires_at"`
			Depth     int    `json:"depth"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	color.New(color.Bold).Fprintf(os.Stdout, "Delegation Chain for %s\n\n", resp.AgentID)

	if len(resp.Chain) == 0 {
		fmt.Fprintln(os.Stdout, "  No delegation chain found.")
		return nil
	}

	for i, link := range resp.Chain {
		prefix := "├─"
		if i == len(resp.Chain)-1 {
			prefix = "└─"
		}
		fmt.Fprintf(os.Stdout, "  %s [%d] %s → %s  (scope: %s, expires: %s)\n",
			prefix, link.Depth, link.FromAgent, link.ToAgent, link.Scope, link.ExpiresAt)
	}
	fmt.Println()

	return nil
}

func truncateToken(token string) string {
	if len(token) <= 20 {
		return token
	}
	return token[:12] + "…" + token[len(token)-4:]
}
