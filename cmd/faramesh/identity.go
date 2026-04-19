package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func identitySocketRequestWithHTTPFallback(op string, payload map[string]any, httpMethod, httpPath string) (json.RawMessage, error) {
	req := map[string]any{"type": "identity", "op": op}
	for k, v := range payload {
		req[k] = v
	}
	resp, err := daemonSocketRequest(req)
	if err == nil {
		return resp, nil
	}
	if !daemonHTTPFallback {
		return nil, err
	}
	if httpMethod == "GET" {
		return daemonGet(httpPath)
	}
	return daemonPost(httpPath, payload)
}

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage workload and agent identity",
	Long: `Verify, attest, and federate agent identities. Supports SPIFFE-based
workload identity, trust bundle management, and external IdP federation.`,
	Args: cobra.NoArgs,
	RunE: runIdentityStatus,
}

var identityStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show identity readiness summary",
	Args:  cobra.NoArgs,
	RunE:  runIdentityStatus,
}

func runIdentityStatus(_ *cobra.Command, _ []string) error {
	out := map[string]any{}
	warnings := map[string]string{}

	if raw, err := identitySocketRequestWithHTTPFallback("whoami", map[string]any{}, "GET", "/api/v1/identity/whoami"); err != nil {
		warnings["whoami"] = err.Error()
	} else {
		out["whoami"] = decodeIdentityStatusPayload(raw)
	}

	if raw, err := identitySocketRequestWithHTTPFallback("trust_level", map[string]any{}, "GET", "/api/v1/identity/trust-level"); err != nil {
		warnings["trust_level"] = err.Error()
	} else {
		out["trust_level"] = decodeIdentityStatusPayload(raw)
	}

	if raw, err := identitySocketRequestWithHTTPFallback("verify", map[string]any{}, "POST", "/api/v1/identity/verify"); err != nil {
		warnings["verify"] = err.Error()
	} else {
		out["verify"] = decodeIdentityStatusPayload(raw)
	}

	if len(out) == 0 {
		for _, key := range []string{"whoami", "trust_level", "verify"} {
			if msg := strings.TrimSpace(warnings[key]); msg != "" {
				return fmt.Errorf("identity status unavailable: %s", msg)
			}
		}
		return fmt.Errorf("identity status unavailable")
	}

	if len(warnings) > 0 {
		out["warnings"] = warnings
	}

	body, _ := json.Marshal(out)
	printResponse("Identity Status", body)
	if len(warnings) > 0 {
		printWarningLine("partial identity status; review warnings field")
	}
	return nil
}

func decodeIdentityStatusPayload(raw json.RawMessage) any {
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return strings.TrimSpace(string(raw))
	}
	return payload
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
		data, err := identitySocketRequestWithHTTPFallback("verify", body, "POST", "/api/v1/identity/verify")
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
		data, err := identitySocketRequestWithHTTPFallback("trust", body, "POST", "/api/v1/identity/trust")
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
		data, err := identitySocketRequestWithHTTPFallback("whoami", map[string]any{}, "GET", "/api/v1/identity/whoami")
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
		data, err := identitySocketRequestWithHTTPFallback("attest", body, "POST", "/api/v1/identity/attest")
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
		data, err := identitySocketRequestWithHTTPFallback("federation_add", body, "POST", "/api/v1/identity/federation/add")
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
		data, err := identitySocketRequestWithHTTPFallback("federation_list", map[string]any{}, "GET", "/api/v1/identity/federation/list")
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
		data, err := identitySocketRequestWithHTTPFallback("federation_revoke", body, "POST", "/api/v1/identity/federation/revoke")
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
		data, err := identitySocketRequestWithHTTPFallback("trust_level", map[string]any{}, "GET", "/api/v1/identity/trust-level")
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

	identityCmd.AddCommand(identityStatusCmd)
	identityCmd.AddCommand(identityVerifyCmd)
	identityCmd.AddCommand(identityTrustCmd)
	identityCmd.AddCommand(identityWhoamiCmd)
	identityCmd.AddCommand(identityAttestCmd)
	identityCmd.AddCommand(identityFederationCmd)
	identityCmd.AddCommand(identityTrustLevelCmd)
}
