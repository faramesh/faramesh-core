package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/compensation"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var (
	compensateDB       string
	compensateDataDir  string
	compensatePolicy   string
	compensateArgsJSON string
	compensateFormat   string
)

type compensateOperation struct {
	ToolID string         `json:"tool_id"`
	Args   map[string]any `json:"args,omitempty"`
}

type compensateOutput struct {
	RecordID  string               `json:"record_id"`
	Status    string               `json:"status"`
	Reason    string               `json:"reason"`
	Operation *compensateOperation `json:"operation,omitempty"`
}

func compensateSocketRequestWithHTTPFallback(op string, payload map[string]any, httpMethod, httpPath string, httpQuery map[string]string) (json.RawMessage, error) {
	req := map[string]any{"type": "compensate", "op": op}
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

var compensateCmd = &cobra.Command{
	Use:   "compensate",
	Short: "Compensation operations: build, list, inspect, apply, status, retry",
}

var compensateBuildCmd = &cobra.Command{
	Use:   "build <record-id>",
	Short: "Build compensation operation for a DPR record",
	Args:  cobra.ExactArgs(1),
	RunE:  runCompensateCommand,
}

var compensateListAgent string

var compensateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List compensation records (optionally filtered by agent)",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		q := map[string]string{}
		payload := map[string]any{}
		if compensateListAgent != "" {
			q["agent"] = compensateListAgent
			payload["agent"] = compensateListAgent
		}
		raw, err := compensateSocketRequestWithHTTPFallback("list", payload, "GET", "/api/v1/compensate/list", q)
		if err != nil {
			return err
		}
		printResponse("Compensations", raw)
		return nil
	},
}

var compensateInspectCmd = &cobra.Command{
	Use:   "inspect <compensation-id>",
	Short: "Show details for a compensation record",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := compensateSocketRequestWithHTTPFallback("inspect", map[string]any{"id": args[0]}, "GET", "/api/v1/compensate/inspect", map[string]string{"id": args[0]})
		if err != nil {
			return err
		}
		printResponse("Compensation Detail", raw)
		return nil
	},
}

var compensateApplyCmd = &cobra.Command{
	Use:   "apply <compensation-id>",
	Short: "Execute a previously-built compensation",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := compensateSocketRequestWithHTTPFallback("apply", map[string]any{"id": args[0]}, "POST", "/api/v1/compensate/apply", nil)
		if err != nil {
			return err
		}
		printResponse("Compensation Apply", raw)
		return nil
	},
}

var compensateStatusCmd = &cobra.Command{
	Use:   "status <compensation-id>",
	Short: "Check execution status of a compensation",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		raw, err := compensateSocketRequestWithHTTPFallback("status", map[string]any{"id": args[0]}, "GET", "/api/v1/compensate/status", map[string]string{"id": args[0]})
		if err != nil {
			return err
		}
		printResponse("Compensation Status", raw)
		return nil
	},
}

var compensateRetryFromStep string

var compensateRetryCmd = &cobra.Command{
	Use:   "retry <compensation-id>",
	Short: "Retry a failed compensation (optionally from a specific step)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		body := map[string]any{"id": args[0]}
		if compensateRetryFromStep != "" {
			body["from_step"] = compensateRetryFromStep
		}
		raw, err := compensateSocketRequestWithHTTPFallback("retry", body, "POST", "/api/v1/compensate/retry", nil)
		if err != nil {
			return err
		}
		printResponse("Compensation Retry", raw)
		return nil
	},
}

func init() {
	compensateBuildCmd.Flags().StringVar(&compensateDB, "db", "", "path to DPR SQLite database (default: <data-dir>/faramesh.db)")
	compensateBuildCmd.Flags().StringVar(&compensateDataDir, "data-dir", "", "directory containing faramesh.db (default: $TMPDIR/faramesh)")
	compensateBuildCmd.Flags().StringVar(&compensatePolicy, "policy", "policy.yaml", "path to policy YAML containing compensation mappings")
	compensateBuildCmd.Flags().StringVar(&compensateArgsJSON, "args", "", "JSON object with original tool args for compensation arg mapping")
	compensateBuildCmd.Flags().StringVar(&compensateFormat, "format", "json", "output format: json|text")

	compensateListCmd.Flags().StringVar(&compensateListAgent, "agent", "", "filter by agent ID")
	compensateRetryCmd.Flags().StringVar(&compensateRetryFromStep, "from-step", "", "resume from a specific step")

	compensateCmd.AddCommand(compensateBuildCmd)
	compensateCmd.AddCommand(compensateListCmd)
	compensateCmd.AddCommand(compensateInspectCmd)
	compensateCmd.AddCommand(compensateApplyCmd)
	compensateCmd.AddCommand(compensateStatusCmd)
	compensateCmd.AddCommand(compensateRetryCmd)
}

func runCompensateCommand(_ *cobra.Command, args []string) error {
	recordID := strings.TrimSpace(args[0])
	if recordID == "" {
		return fmt.Errorf("record id is required")
	}
	return runCompensate(recordID, compensatePolicy, resolveCompensateDBPath(), compensateArgsJSON, strings.ToLower(strings.TrimSpace(compensateFormat)), os.Stdout)
}

func runCompensate(recordID, policyPath, dbPath, argsJSON, format string, out io.Writer) error {
	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	engine := compensation.NewEngine(doc)

	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	rec, err := store.ByID(recordID)
	if err != nil {
		return fmt.Errorf("lookup DPR record %s: %w", recordID, err)
	}

	originalArgs := map[string]any{}
	if strings.TrimSpace(argsJSON) != "" {
		if err := json.Unmarshal([]byte(argsJSON), &originalArgs); err != nil {
			return fmt.Errorf("parse --args JSON: %w", err)
		}
	}

	result := buildCompensateOutput(engine, rec, originalArgs)

	if format == "" || format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	if format != "text" {
		return fmt.Errorf("unsupported format %q (use json|text)", format)
	}
	writeCompensateText(out, result)
	return nil
}

func buildCompensateOutput(engine *compensation.Engine, rec *dpr.Record, originalArgs map[string]any) compensateOutput {
	result := compensateOutput{
		RecordID: rec.RecordID,
	}
	classification := engine.Classify(rec.ToolID)
	switch classification {
	case compensation.Compensatable:
		compRes, err := engine.BuildCompensation(compensation.CompensationRequest{
			OriginalRecordID: rec.RecordID,
			OriginalToolID:   rec.ToolID,
			OriginalArgs:     originalArgs,
			Reason:           "manual compensation request",
			RequestedBy:      "faramesh compensate",
		})
		if err != nil {
			result.Status = "unsupported"
			result.Reason = err.Error()
			return result
		}
		switch compRes.Status {
		case compensation.StatusExecuted:
			result.Status = "proposed"
			result.Reason = "compensation operation generated"
			result.Operation = &compensateOperation{
				ToolID: compRes.CompensationToolID,
				Args:   compRes.CompensationArgs,
			}
		case compensation.StatusNotSupported:
			result.Status = "unsupported"
			result.Reason = compRes.Error
		default:
			result.Status = "no_compensation"
			result.Reason = compRes.Error
		}
	case compensation.Reversible:
		result.Status = "no_compensation"
		result.Reason = "tool is reversible; no compensating tool call required"
	default:
		result.Status = "unsupported"
		result.Reason = "tool is not compensatable"
	}
	return result
}

func resolveCompensateDBPath() string {
	if strings.TrimSpace(compensateDB) != "" {
		return strings.TrimSpace(compensateDB)
	}
	dataDir := strings.TrimSpace(compensateDataDir)
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), "faramesh")
	}
	return filepath.Join(dataDir, "faramesh.db")
}

func writeCompensateText(out io.Writer, result compensateOutput) {
	fmt.Fprintf(out, "record_id: %s\n", result.RecordID)
	fmt.Fprintf(out, "status: %s\n", result.Status)
	fmt.Fprintf(out, "reason: %s\n", result.Reason)
	if result.Operation == nil {
		return
	}
	fmt.Fprintf(out, "tool_id: %s\n", result.Operation.ToolID)
	keys := make([]string, 0, len(result.Operation.Args))
	for k := range result.Operation.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(out, "arg.%s: %v\n", k, result.Operation.Args[k])
	}
}
