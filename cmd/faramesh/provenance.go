package main

import (
	"net/url"

	"github.com/spf13/cobra"
)

var provenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Manage agent provenance attestations",
	Long: `Sign, verify, and inspect provenance records for AI agents. Provenance
attestations capture the agent's model, framework, tools, and configuration
at the time of signing, enabling drift detection and compliance verification.`,
}

// ── provenance sign ─────────────────────────────────────────────────────────

var (
	provSignAgent     string
	provSignModel     string
	provSignFramework string
	provSignTools     string
	provSignKey       string
)

var provenanceSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create a signed provenance attestation for an agent",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		body := map[string]any{}
		if cmd.Flags().Changed("agent") {
			body["agent_id"] = provSignAgent
		}
		if cmd.Flags().Changed("model") {
			body["model"] = provSignModel
		}
		if cmd.Flags().Changed("framework") {
			body["framework"] = provSignFramework
		}
		if cmd.Flags().Changed("tools") {
			body["tools"] = provSignTools
		}
		if cmd.Flags().Changed("key") {
			body["signing_key"] = provSignKey
		}
		data, err := daemonPost("/api/v1/provenance/sign", body)
		if err != nil {
			return err
		}
		printHeader("Provenance Signed")
		printJSON(data)
		return nil
	},
}

// ── provenance verify ───────────────────────────────────────────────────────

var provenanceVerifyCmd = &cobra.Command{
	Use:   "verify <agent-id>",
	Short: "Verify an agent's provenance attestation",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		data, err := daemonGet("/api/v1/provenance/verify/" + url.PathEscape(args[0]))
		if err != nil {
			return err
		}
		printHeader("Provenance Verification")
		printJSON(data)
		return nil
	},
}

// ── provenance inspect ──────────────────────────────────────────────────────

var provenanceInspectCmd = &cobra.Command{
	Use:   "inspect <agent-id>",
	Short: "Inspect a provenance attestation's full details",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		data, err := daemonGet("/api/v1/provenance/inspect/" + url.PathEscape(args[0]))
		if err != nil {
			return err
		}
		printHeader("Provenance Details")
		printJSON(data)
		return nil
	},
}

// ── provenance diff ─────────────────────────────────────────────────────────

var provenanceDiffCmd = &cobra.Command{
	Use:   "diff <agent-id>",
	Short: "Show drift between current agent state and signed provenance",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		data, err := daemonGet("/api/v1/provenance/diff/" + url.PathEscape(args[0]))
		if err != nil {
			return err
		}
		printHeader("Provenance Diff")
		printJSON(data)
		return nil
	},
}

// ── provenance list ─────────────────────────────────────────────────────────

var provenanceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all provenance attestations",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := daemonGet("/api/v1/provenance/list")
		if err != nil {
			return err
		}
		printHeader("Provenance Attestations")
		printJSON(data)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(provenanceCmd)

	provenanceSignCmd.Flags().StringVar(&provSignAgent, "agent", "", "agent ID to sign provenance for")
	provenanceSignCmd.Flags().StringVar(&provSignModel, "model", "", "model identifier (e.g. gpt-4, claude-3)")
	provenanceSignCmd.Flags().StringVar(&provSignFramework, "framework", "", "framework name (e.g. langchain, crewai)")
	provenanceSignCmd.Flags().StringVar(&provSignTools, "tools", "", "comma-separated list of tool names")
	provenanceSignCmd.Flags().StringVar(&provSignKey, "key", "", "path to signing key")

	provenanceCmd.AddCommand(provenanceSignCmd)
	provenanceCmd.AddCommand(provenanceVerifyCmd)
	provenanceCmd.AddCommand(provenanceInspectCmd)
	provenanceCmd.AddCommand(provenanceDiffCmd)
	provenanceCmd.AddCommand(provenanceListCmd)
}
