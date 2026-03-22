package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var opsCmd = &cobra.Command{
	Use:   "ops",
	Short: "Operator commands: policy changes, audit, authentication",
}

var opsPolicyChangeCmd = &cobra.Command{
	Use:   "policy-change",
	Short: "Manage policy change proposals",
}

var opsPCProposeReason string

var opsPolicyChangeProposeCmd = &cobra.Command{
	Use:   "propose <policy.yaml>",
	Short: "Propose a policy change from a YAML file",
	Args:  cobra.ExactArgs(1),
	RunE:  runOpsPCPropose,
}

var opsPolicyChangeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List pending policy change proposals",
	Args:  cobra.NoArgs,
	RunE:  runOpsPCList,
}

var (
	opsPCApproveIdentity string
	opsPCApproveMFA      string
)

var opsPolicyChangeApproveCmd = &cobra.Command{
	Use:   "approve <proposal-id>",
	Short: "Approve a policy change proposal",
	Args:  cobra.ExactArgs(1),
	RunE:  runOpsPCApprove,
}

var opsPolicyChangeRejectCmd = &cobra.Command{
	Use:   "reject <proposal-id>",
	Short: "Reject a policy change proposal",
	Args:  cobra.ExactArgs(1),
	RunE:  runOpsPCReject,
}

var (
	opsAuditWindow   string
	opsAuditOperator string
)

var opsAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Query the operator audit log",
	Args:  cobra.NoArgs,
	RunE:  runOpsAudit,
}

var (
	opsLoginSSO bool
	opsLoginKey string
)

var opsLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate as an operator",
	Args:  cobra.NoArgs,
	RunE:  runOpsLogin,
}

var opsLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "End the current operator session",
	Args:  cobra.NoArgs,
	RunE:  runOpsLogout,
}

var opsWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the current authenticated operator identity",
	Args:  cobra.NoArgs,
	RunE:  runOpsWhoami,
}

func init() {
	opsPolicyChangeProposeCmd.Flags().StringVar(&opsPCProposeReason, "reason", "", "reason for the policy change")
	_ = opsPolicyChangeProposeCmd.MarkFlagRequired("reason")

	opsPolicyChangeApproveCmd.Flags().StringVar(&opsPCApproveIdentity, "identity", "", "approver identity")
	opsPolicyChangeApproveCmd.Flags().StringVar(&opsPCApproveMFA, "mfa-token", "", "MFA token for approval verification")

	opsAuditCmd.Flags().StringVar(&opsAuditWindow, "window", "24h", "time window for audit log query")
	opsAuditCmd.Flags().StringVar(&opsAuditOperator, "operator", "", "filter by operator identity")

	opsLoginCmd.Flags().BoolVar(&opsLoginSSO, "sso", false, "authenticate via SSO")
	opsLoginCmd.Flags().StringVar(&opsLoginKey, "key", "", "authenticate with an API key")

	opsPolicyChangeCmd.AddCommand(
		opsPolicyChangeProposeCmd, opsPolicyChangeListCmd,
		opsPolicyChangeApproveCmd, opsPolicyChangeRejectCmd,
	)
	opsCmd.AddCommand(opsPolicyChangeCmd, opsAuditCmd, opsLoginCmd, opsLogoutCmd, opsWhoamiCmd)
	rootCmd.AddCommand(opsCmd)
}

func runOpsPCPropose(_ *cobra.Command, args []string) error {
	content, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}
	resp, err := daemonPost("/api/v1/ops/policy-change/propose", map[string]any{
		"policy_yaml": string(content),
		"reason":      opsPCProposeReason,
	})
	if err != nil {
		return err
	}
	printResponse("Policy Change Proposed", resp)
	return nil
}

func runOpsPCList(_ *cobra.Command, _ []string) error {
	resp, err := daemonGet("/api/v1/ops/policy-change/list")
	if err != nil {
		return err
	}
	printResponse("Policy Change Proposals", resp)
	return nil
}

func runOpsPCApprove(_ *cobra.Command, args []string) error {
	body := map[string]any{
		"proposal_id": args[0],
	}
	if opsPCApproveIdentity != "" {
		body["identity"] = opsPCApproveIdentity
	}
	if opsPCApproveMFA != "" {
		body["mfa_token"] = opsPCApproveMFA
	}
	resp, err := daemonPost("/api/v1/ops/policy-change/approve", body)
	if err != nil {
		return err
	}
	printResponse("Policy Change Approved", resp)
	return nil
}

func runOpsPCReject(_ *cobra.Command, args []string) error {
	resp, err := daemonPost("/api/v1/ops/policy-change/reject", map[string]any{
		"proposal_id": args[0],
	})
	if err != nil {
		return err
	}
	printResponse("Policy Change Rejected", resp)
	return nil
}

func runOpsAudit(_ *cobra.Command, _ []string) error {
	resp, err := daemonGetWithQuery("/api/v1/ops/audit", map[string]string{
		"window":   opsAuditWindow,
		"operator": opsAuditOperator,
	})
	if err != nil {
		return err
	}
	printResponse("Operator Audit Log", resp)
	return nil
}

func runOpsLogin(_ *cobra.Command, _ []string) error {
	body := map[string]any{
		"sso": opsLoginSSO,
	}
	if opsLoginKey != "" {
		body["key"] = opsLoginKey
	}
	resp, err := daemonPost("/api/v1/ops/login", body)
	if err != nil {
		return err
	}
	printResponse("Operator Login", resp)
	return nil
}

func runOpsLogout(_ *cobra.Command, _ []string) error {
	resp, err := daemonPost("/api/v1/ops/logout", map[string]any{})
	if err != nil {
		return err
	}
	printResponse("Operator Logout", resp)
	return nil
}

func runOpsWhoami(_ *cobra.Command, _ []string) error {
	resp, err := daemonGet("/api/v1/ops/whoami")
	if err != nil {
		return err
	}
	printResponse("Operator Identity", resp)
	return nil
}
