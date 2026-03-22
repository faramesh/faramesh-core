package main

import (
	"github.com/spf13/cobra"
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage workload and agent identity",
	Long: `Verify, attest, and federate agent identities. Supports SPIFFE-based
workload identity, trust bundle management, and external IdP federation.`,
}

// ── identity verify ─────────────────────────────────────────────────────────

var identityVerifySPIFFE string

var identityVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the current workload identity",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("spiffe") {
			body["spiffe_id"] = identityVerifySPIFFE
		}
		data, err := daemonPost("/api/v1/identity/verify", body)
		if err != nil {
			return err
		}
		printHeader("Identity Verification")
		printJSON(data)
		return nil
	},
}

// ── identity trust ──────────────────────────────────────────────────────────

var (
	identityTrustDomain string
	identityTrustBundle string
)

var identityTrustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Configure a trust domain and bundle",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("domain") {
			body["domain"] = identityTrustDomain
		}
		if cmd.Flags().Changed("bundle") {
			body["bundle"] = identityTrustBundle
		}
		data, err := daemonPost("/api/v1/identity/trust", body)
		if err != nil {
			return err
		}
		printHeader("Trust Configuration")
		printJSON(data)
		return nil
	},
}

// ── identity whoami ─────────────────────────────────────────────────────────

var identityWhoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display the current agent identity",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := daemonGet("/api/v1/identity/whoami")
		if err != nil {
			return err
		}
		printHeader("Current Identity")
		printJSON(data)
		return nil
	},
}

// ── identity attest ─────────────────────────────────────────────────────────

var identityAttestWorkload string

var identityAttestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Attest the current workload identity",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("workload") {
			body["workload"] = identityAttestWorkload
		}
		data, err := daemonPost("/api/v1/identity/attest", body)
		if err != nil {
			return err
		}
		printHeader("Workload Attestation")
		printJSON(data)
		return nil
	},
}

// ── identity federation ─────────────────────────────────────────────────────

var identityFederationCmd = &cobra.Command{
	Use:   "federation",
	Short: "Manage identity provider federations",
}

var (
	identityFedAddIDP      string
	identityFedAddClientID string
	identityFedAddScope    string
)

var identityFederationAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add an identity provider federation",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("idp") {
			body["idp"] = identityFedAddIDP
		}
		if cmd.Flags().Changed("client-id") {
			body["client_id"] = identityFedAddClientID
		}
		if cmd.Flags().Changed("scope") {
			body["scope"] = identityFedAddScope
		}
		data, err := daemonPost("/api/v1/identity/federation/add", body)
		if err != nil {
			return err
		}
		printHeader("Federation Added")
		printJSON(data)
		return nil
	},
}

var identityFederationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured identity federations",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := daemonGet("/api/v1/identity/federation/list")
		if err != nil {
			return err
		}
		printHeader("Identity Federations")
		printJSON(data)
		return nil
	},
}

var identityFedRevokeIDP string

var identityFederationRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an identity provider federation",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("idp") {
			body["idp"] = identityFedRevokeIDP
		}
		data, err := daemonPost("/api/v1/identity/federation/revoke", body)
		if err != nil {
			return err
		}
		printHeader("Federation Revoked")
		printJSON(data)
		return nil
	},
}

// ── identity trust-level ────────────────────────────────────────────────────

var identityTrustLevelCmd = &cobra.Command{
	Use:   "trust-level",
	Short: "Display the computed trust level for the current environment",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := daemonGet("/api/v1/identity/trust-level")
		if err != nil {
			return err
		}
		printHeader("Trust Level")
		printJSON(data)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(identityCmd)

	identityVerifyCmd.Flags().StringVar(&identityVerifySPIFFE, "spiffe", "", "SPIFFE ID to verify (e.g. spiffe://example.org/agent)")

	identityTrustCmd.Flags().StringVar(&identityTrustDomain, "domain", "", "SPIFFE trust domain")
	identityTrustCmd.Flags().StringVar(&identityTrustBundle, "bundle", "", "path to trust bundle PEM file")

	identityAttestCmd.Flags().StringVar(&identityAttestWorkload, "workload", "", "workload identifier for attestation")

	identityFederationAddCmd.Flags().StringVar(&identityFedAddIDP, "idp", "", "identity provider URL")
	identityFederationAddCmd.Flags().StringVar(&identityFedAddClientID, "client-id", "", "OAuth2 client ID")
	identityFederationAddCmd.Flags().StringVar(&identityFedAddScope, "scope", "", "OAuth2 scope")

	identityFederationRevokeCmd.Flags().StringVar(&identityFedRevokeIDP, "idp", "", "identity provider URL to revoke")

	identityFederationCmd.AddCommand(identityFederationAddCmd)
	identityFederationCmd.AddCommand(identityFederationListCmd)
	identityFederationCmd.AddCommand(identityFederationRevokeCmd)

	identityCmd.AddCommand(identityVerifyCmd)
	identityCmd.AddCommand(identityTrustCmd)
	identityCmd.AddCommand(identityWhoamiCmd)
	identityCmd.AddCommand(identityAttestCmd)
	identityCmd.AddCommand(identityFederationCmd)
	identityCmd.AddCommand(identityTrustLevelCmd)
}
