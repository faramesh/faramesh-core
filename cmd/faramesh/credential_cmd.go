package main

import (
	"encoding/json"
	"net/url"

	"github.com/spf13/cobra"
)

func credentialSocketRequestWithHTTPFallback(op string, payload map[string]any, httpMethod, httpPath string) (json.RawMessage, error) {
	req := map[string]any{"type": "credential", "op": op}
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

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage credential broker registrations",
	Long: `Register, inspect, rotate, and revoke credentials managed by the
Faramesh credential broker. The broker mediates all credential access for
governed agents, enforcing scope restrictions and audit trails.`,
}

// ── credential register ─────────────────────────────────────────────────────

var (
	credRegisterKey      string
	credRegisterScope    string
	credRegisterMaxScope string
)

var credentialRegisterCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register a new credential with the broker",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"name": args[0]}
		if cmd.Flags().Changed("key") {
			body["key"] = credRegisterKey
		}
		if cmd.Flags().Changed("scope") {
			body["scope"] = credRegisterScope
		}
		if cmd.Flags().Changed("max-scope") {
			body["max_scope"] = credRegisterMaxScope
		}
		data, err := credentialSocketRequestWithHTTPFallback("register", body, "POST", "/api/v1/credential/register")
		if err != nil {
			return err
		}
		printHeader("Credential Registered")
		printJSON(data)
		return nil
	},
}

// ── credential list ─────────────────────────────────────────────────────────

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered credentials",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := credentialSocketRequestWithHTTPFallback("list", map[string]any{}, "GET", "/api/v1/credential/list")
		if err != nil {
			return err
		}
		printHeader("Credentials")
		printJSON(data)
		return nil
	},
}

// ── credential inspect ──────────────────────────────────────────────────────

var credentialInspectCmd = &cobra.Command{
	Use:   "inspect <name>",
	Short: "Inspect a credential's metadata and usage",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		httpPath := "/api/v1/credential/inspect/" + url.PathEscape(args[0])
		data, err := credentialSocketRequestWithHTTPFallback("inspect", map[string]any{"name": args[0]}, "GET", httpPath)
		if err != nil {
			return err
		}
		printHeader("Credential Details")
		printJSON(data)
		return nil
	},
}

// ── credential rotate ───────────────────────────────────────────────────────

var credRotateKey string

var credentialRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Rotate a credential's key material",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"name": args[0]}
		if cmd.Flags().Changed("key") {
			body["key"] = credRotateKey
		}
		data, err := credentialSocketRequestWithHTTPFallback("rotate", body, "POST", "/api/v1/credential/rotate")
		if err != nil {
			return err
		}
		printHeader("Credential Rotated")
		printJSON(data)
		return nil
	},
}

// ── credential health ───────────────────────────────────────────────────────

var credentialHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check health of all credential backends",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := credentialSocketRequestWithHTTPFallback("health", map[string]any{}, "GET", "/api/v1/credential/health")
		if err != nil {
			return err
		}
		printHeader("Credential Backend Health")
		printJSON(data)
		return nil
	},
}

// ── credential map ──────────────────────────────────────────────────────────

var credentialMapCmd = &cobra.Command{
	Use:   "map",
	Short: "Show policy-to-broker routing map",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := credentialSocketRequestWithHTTPFallback("routing_map", map[string]any{}, "GET", "/api/v1/credential/map")
		if err != nil {
			return err
		}
		printHeader("Credential Broker Routing")
		printJSON(data)
		return nil
	},
}

// ── credential revoke ───────────────────────────────────────────────────────

var credentialRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke a credential and invalidate active leases",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		body := map[string]any{"name": args[0]}
		data, err := credentialSocketRequestWithHTTPFallback("revoke", body, "POST", "/api/v1/credential/revoke")
		if err != nil {
			return err
		}
		printHeader("Credential Revoked")
		printJSON(data)
		return nil
	},
}

// ── credential audit ────────────────────────────────────────────────────────

var credAuditWindow string

var credentialAuditCmd = &cobra.Command{
	Use:   "audit <name>",
	Short: "View audit log for a credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "/api/v1/credential/audit/" + url.PathEscape(args[0])
		payload := map[string]any{"name": args[0]}
		if cmd.Flags().Changed("window") {
			payload["window"] = credAuditWindow
			path += "?" + url.Values{"window": {credAuditWindow}}.Encode()
		}
		data, err := credentialSocketRequestWithHTTPFallback("audit", payload, "GET", path)
		if err != nil {
			return err
		}
		printHeader("Credential Audit Log")
		printJSON(data)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(credentialCmd)

	credentialRegisterCmd.Flags().StringVar(&credRegisterKey, "key", "", "credential key or secret value")
	credentialRegisterCmd.Flags().StringVar(&credRegisterScope, "scope", "", "allowed scope for this credential")
	credentialRegisterCmd.Flags().StringVar(&credRegisterMaxScope, "max-scope", "", "maximum scope ceiling")

	credentialRotateCmd.Flags().StringVar(&credRotateKey, "key", "", "new key material")

	credentialAuditCmd.Flags().StringVar(&credAuditWindow, "window", "", "audit time window (e.g. 24h, 7d)")

	credentialCmd.AddCommand(credentialRegisterCmd)
	credentialCmd.AddCommand(credentialListCmd)
	credentialCmd.AddCommand(credentialInspectCmd)
	credentialCmd.AddCommand(credentialRotateCmd)
	credentialCmd.AddCommand(credentialHealthCmd)
	credentialCmd.AddCommand(credentialMapCmd)
	credentialCmd.AddCommand(credentialRevokeCmd)
	credentialCmd.AddCommand(credentialAuditCmd)
	credentialCmd.AddCommand(credentialVaultCmd)
}
