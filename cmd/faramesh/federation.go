package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type federationTrustEntry struct {
	TrustID   string `json:"trust_id"`
	Org       string `json:"org"`
	Scope     string `json:"scope"`
	CreatedAt string `json:"created_at"`
	Active    bool   `json:"active"`
}

var federationCmd = &cobra.Command{
	Use:   "federation",
	Short: "Cross-organization federation and trust management",
	Long: `Manage federation trust bundles between organizations and issue or verify
cross-org governance receipts for auditable inter-tenant operations.`,
}

var federationTrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage federation trust relationships",
}

var federationReceiptCmd = &cobra.Command{
	Use:   "receipt",
	Short: "Issue and verify cross-org governance receipts",
}

var federationTrustAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a federation trust relationship",
	Args:  cobra.NoArgs,
	RunE:  runFederationTrustAdd,
}

var federationTrustListCmd = &cobra.Command{
	Use:   "list",
	Short: "List federation trust relationships",
	Args:  cobra.NoArgs,
	RunE:  runFederationTrustList,
}

var federationTrustRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a federation trust relationship",
	Args:  cobra.NoArgs,
	RunE:  runFederationTrustRevoke,
}

var federationReceiptVerifyCmd = &cobra.Command{
	Use:   "verify <receipt-token>",
	Short: "Verify a cross-org governance receipt",
	Args:  cobra.ExactArgs(1),
	RunE:  runFederationReceiptVerify,
}

var federationReceiptIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a cross-org governance receipt",
	Args:  cobra.NoArgs,
	RunE:  runFederationReceiptIssue,
}

var (
	fedTrustAddOrg    string
	fedTrustAddBundle string
	fedTrustAddScope  string

	fedTrustRevokeOrg string

	fedReceiptIssueRecordID string
	fedReceiptIssueForOrg   string
	fedReceiptIssueKey      string
)

func init() {
	federationTrustAddCmd.Flags().StringVar(&fedTrustAddOrg, "org", "", "organization identifier")
	federationTrustAddCmd.Flags().StringVar(&fedTrustAddBundle, "bundle", "", "path to trust bundle file (PEM)")
	federationTrustAddCmd.Flags().StringVar(&fedTrustAddScope, "scope", "*", "scope of trust (tool pattern)")
	_ = federationTrustAddCmd.MarkFlagRequired("org")
	_ = federationTrustAddCmd.MarkFlagRequired("bundle")

	federationTrustRevokeCmd.Flags().StringVar(&fedTrustRevokeOrg, "org", "", "organization to revoke trust for")
	_ = federationTrustRevokeCmd.MarkFlagRequired("org")

	federationReceiptIssueCmd.Flags().StringVar(&fedReceiptIssueRecordID, "record-id", "", "DPR record ID to attest")
	federationReceiptIssueCmd.Flags().StringVar(&fedReceiptIssueForOrg, "for", "", "recipient organization")
	federationReceiptIssueCmd.Flags().StringVar(&fedReceiptIssueKey, "key", "", "signing key path (PEM)")
	_ = federationReceiptIssueCmd.MarkFlagRequired("record-id")
	_ = federationReceiptIssueCmd.MarkFlagRequired("for")
	_ = federationReceiptIssueCmd.MarkFlagRequired("key")

	federationTrustCmd.AddCommand(federationTrustAddCmd, federationTrustListCmd, federationTrustRevokeCmd)
	federationReceiptCmd.AddCommand(federationReceiptVerifyCmd, federationReceiptIssueCmd)
	federationCmd.AddCommand(federationTrustCmd, federationReceiptCmd)
	rootCmd.AddCommand(federationCmd)
}

func runFederationTrustAdd(_ *cobra.Command, _ []string) error {
	bundleData, err := os.ReadFile(fedTrustAddBundle)
	if err != nil {
		return fmt.Errorf("read trust bundle: %w", err)
	}

	req := map[string]string{
		"org":    fedTrustAddOrg,
		"bundle": string(bundleData),
		"scope":  fedTrustAddScope,
	}

	raw, err := daemonPost("/api/v1/federation/trust", req)
	if err != nil {
		return err
	}

	var resp struct {
		TrustID   string `json:"trust_id"`
		Org       string `json:"org"`
		Scope     string `json:"scope"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	color.New(color.FgGreen, color.Bold).Fprintln(os.Stdout, "✓ Federation trust established")
	fmt.Println()
	fmt.Fprintf(os.Stdout, "  Trust ID:  %s\n", resp.TrustID)
	fmt.Fprintf(os.Stdout, "  Org:       %s\n", resp.Org)
	fmt.Fprintf(os.Stdout, "  Scope:     %s\n", resp.Scope)
	fmt.Fprintf(os.Stdout, "  Created:   %s\n", resp.CreatedAt)
	fmt.Println()

	return nil
}

func runFederationTrustList(_ *cobra.Command, _ []string) error {
	raw, err := daemonGet("/api/v1/federation/trust")
	if err != nil {
		return err
	}

	var resp struct {
		Trusts []federationTrustEntry `json:"trusts"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	color.New(color.Bold).Fprintln(os.Stdout, "Federation Trust Relationships")
	fmt.Println()

	if len(resp.Trusts) == 0 {
		fmt.Fprintln(os.Stdout, "  No trust relationships configured.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  TRUST ID\tORG\tSCOPE\tCREATED\tACTIVE")
	for _, t := range resp.Trusts {
		active := "yes"
		if !t.Active {
			active = "no"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n",
			t.TrustID, t.Org, t.Scope, t.CreatedAt, active)
	}
	w.Flush()
	fmt.Println()

	return nil
}

func runFederationTrustRevoke(_ *cobra.Command, _ []string) error {
	req := map[string]string{"org": fedTrustRevokeOrg}

	raw, err := daemonPost("/api/v1/federation/trust/revoke", req)
	if err != nil {
		return err
	}

	var resp struct {
		Revoked bool   `json:"revoked"`
		Org     string `json:"org"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if resp.Revoked {
		color.New(color.FgGreen).Fprintf(os.Stdout, "✓ Trust revoked for org %s\n", resp.Org)
	} else {
		color.New(color.FgYellow).Fprintf(os.Stdout, "⚠ %s\n", resp.Message)
	}
	return nil
}

func runFederationReceiptVerify(_ *cobra.Command, args []string) error {
	req := map[string]string{"token": args[0]}

	raw, err := daemonPost("/api/v1/federation/receipt/verify", req)
	if err != nil {
		return err
	}

	var resp struct {
		Valid    bool   `json:"valid"`
		Org      string `json:"org"`
		RecordID string `json:"record_id"`
		IssuedAt string `json:"issued_at"`
		Issuer   string `json:"issuer"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if resp.Valid {
		color.New(color.FgGreen, color.Bold).Fprintln(os.Stdout, "✓ Receipt is valid")
		fmt.Println()
		fmt.Fprintf(os.Stdout, "  Org:       %s\n", resp.Org)
		fmt.Fprintf(os.Stdout, "  Record:    %s\n", resp.RecordID)
		fmt.Fprintf(os.Stdout, "  Issuer:    %s\n", resp.Issuer)
		fmt.Fprintf(os.Stdout, "  Issued at: %s\n", resp.IssuedAt)
	} else {
		color.New(color.FgRed, color.Bold).Fprintln(os.Stdout, "✗ Receipt is invalid")
		fmt.Fprintf(os.Stdout, "  Reason: %s\n", resp.Reason)
	}
	fmt.Println()

	return nil
}

func runFederationReceiptIssue(_ *cobra.Command, _ []string) error {
	keyData, err := os.ReadFile(fedReceiptIssueKey)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}

	req := map[string]string{
		"record_id":   fedReceiptIssueRecordID,
		"for_org":     fedReceiptIssueForOrg,
		"signing_key": string(keyData),
	}

	raw, err := daemonPost("/api/v1/federation/receipt/issue", req)
	if err != nil {
		return err
	}

	var resp struct {
		Token     string `json:"token"`
		RecordID  string `json:"record_id"`
		ForOrg    string `json:"for_org"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	bold := color.New(color.Bold)
	color.New(color.FgGreen, color.Bold).Fprintln(os.Stdout, "✓ Receipt issued")
	fmt.Println()
	bold.Fprintf(os.Stdout, "  Token:     ")
	fmt.Fprintln(os.Stdout, resp.Token)
	fmt.Fprintf(os.Stdout, "  Record:    %s\n", resp.RecordID)
	fmt.Fprintf(os.Stdout, "  For org:   %s\n", resp.ForOrg)
	fmt.Fprintf(os.Stdout, "  Issued at: %s\n", resp.IssuedAt)
	fmt.Fprintf(os.Stdout, "  Expires:   %s\n", resp.ExpiresAt)
	fmt.Println()

	return nil
}
