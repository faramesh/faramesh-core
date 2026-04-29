package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func incidentSocketRequestWithHTTPFallback(op string, payload map[string]any, httpMethod, httpPath string, httpQuery map[string]string) (json.RawMessage, error) {
	req := map[string]any{"type": "incident", "op": op}
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
		if len(httpQuery) > 0 {
			return daemonGetWithQuery(httpPath, httpQuery)
		}
		return daemonGet(httpPath)
	}
	return daemonPost(httpPath, payload)
}

var incidentCmd = &cobra.Command{
	Use:   "incident",
	Short: "Declare, inspect, and manage governance incidents",
}

var (
	incDeclareAgent    string
	incDeclareSeverity string
	incDeclareReason   string
)

var incidentDeclareCmd = &cobra.Command{
	Use:   "declare",
	Short: "Declare a new governance incident",
	Args:  cobra.NoArgs,
	RunE:  runIncidentDeclare,
}

var incidentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all incidents",
	Args:  cobra.NoArgs,
	RunE:  runIncidentList,
}

var incidentInspectCmd = &cobra.Command{
	Use:   "inspect <incident-id>",
	Short: "Inspect an incident by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runIncidentInspect,
}

var incidentIsolateCmd = &cobra.Command{
	Use:   "isolate <agent-id>",
	Short: "Isolate an agent involved in an incident",
	Args:  cobra.ExactArgs(1),
	RunE:  runIncidentIsolate,
}

var incidentEvidenceCmd = &cobra.Command{
	Use:   "evidence <incident-id>",
	Short: "Retrieve evidence artifacts for an incident",
	Args:  cobra.ExactArgs(1),
	RunE:  runIncidentEvidence,
}

var incidentResolveCmd = &cobra.Command{
	Use:   "resolve <incident-id>",
	Short: "Resolve an open incident",
	Args:  cobra.ExactArgs(1),
	RunE:  runIncidentResolve,
}

var incidentPlaybookCmd = &cobra.Command{
	Use:   "playbook <incident-id>",
	Short: "Show the recommended playbook for an incident",
	Args:  cobra.ExactArgs(1),
	RunE:  runIncidentPlaybook,
}

func init() {
	incidentDeclareCmd.Flags().StringVar(&incDeclareAgent, "agent", "", "agent identifier")
	incidentDeclareCmd.Flags().StringVar(&incDeclareSeverity, "severity", "", "severity level (critical, high, medium, low)")
	incidentDeclareCmd.Flags().StringVar(&incDeclareReason, "reason", "", "reason for declaring the incident")
	_ = incidentDeclareCmd.MarkFlagRequired("agent")
	_ = incidentDeclareCmd.MarkFlagRequired("severity")
	_ = incidentDeclareCmd.MarkFlagRequired("reason")

	incidentCmd.AddCommand(
		incidentDeclareCmd, incidentListCmd, incidentInspectCmd,
		incidentIsolateCmd, incidentEvidenceCmd, incidentResolveCmd,
		incidentPlaybookCmd,
	)
	rootCmd.AddCommand(incidentCmd)
}

func runIncidentDeclare(_ *cobra.Command, _ []string) error {
	payload := map[string]any{
		"agent":    incDeclareAgent,
		"severity": incDeclareSeverity,
		"reason":   incDeclareReason,
	}
	resp, err := incidentSocketRequestWithHTTPFallback("declare", payload, "POST", "/api/v1/incident/declare", nil)
	if err != nil {
		return err
	}
	printResponse("Incident Declared", resp)
	return nil
}

func runIncidentList(_ *cobra.Command, _ []string) error {
	resp, err := incidentSocketRequestWithHTTPFallback("list", map[string]any{}, "GET", "/api/v1/incident/list", nil)
	if err != nil {
		return err
	}
	printResponse("Incidents", resp)
	return nil
}

func runIncidentInspect(_ *cobra.Command, args []string) error {
	payload := map[string]any{"id": args[0]}
	resp, err := incidentSocketRequestWithHTTPFallback("inspect", payload, "GET", "/api/v1/incident/inspect", map[string]string{"id": args[0]})
	if err != nil {
		return err
	}
	printResponse(fmt.Sprintf("Incident — %s", args[0]), resp)
	return nil
}

func runIncidentIsolate(_ *cobra.Command, args []string) error {
	payload := map[string]any{"agent_id": args[0]}
	resp, err := incidentSocketRequestWithHTTPFallback("isolate", payload, "POST", "/api/v1/incident/isolate", nil)
	if err != nil {
		return err
	}
	printResponse(fmt.Sprintf("Agent Isolated — %s", args[0]), resp)
	return nil
}

func runIncidentEvidence(_ *cobra.Command, args []string) error {
	payload := map[string]any{"id": args[0]}
	resp, err := incidentSocketRequestWithHTTPFallback("evidence", payload, "GET", "/api/v1/incident/evidence", map[string]string{"id": args[0]})
	if err != nil {
		return err
	}
	printResponse(fmt.Sprintf("Evidence — %s", args[0]), resp)
	return nil
}

func runIncidentResolve(_ *cobra.Command, args []string) error {
	payload := map[string]any{"incident_id": args[0], "id": args[0]}
	resp, err := incidentSocketRequestWithHTTPFallback("resolve", payload, "POST", "/api/v1/incident/resolve", nil)
	if err != nil {
		return err
	}
	printResponse(fmt.Sprintf("Incident Resolved — %s", args[0]), resp)
	return nil
}

func runIncidentPlaybook(_ *cobra.Command, args []string) error {
	payload := map[string]any{"id": args[0]}
	resp, err := incidentSocketRequestWithHTTPFallback("playbook", payload, "GET", "/api/v1/incident/playbook", map[string]string{"id": args[0]})
	if err != nil {
		return err
	}
	printResponse(fmt.Sprintf("Playbook — %s", args[0]), resp)
	return nil
}
