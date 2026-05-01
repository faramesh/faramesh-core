package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

var auditExportCmd = &cobra.Command{
	Use:   "export <dpr.db>",
	Short: "Export DPR records for compliance (SOC2, HIPAA, PCI-DSS)",
	Long: `Export the Decision Provenance Record chain to JSON, CSV, or JSONL
for compliance auditing and external analytics.

  faramesh audit export data/dpr.db --format json > audit.json
  faramesh audit export data/dpr.db --format csv > audit.csv
	faramesh audit export data/dpr.db --format jsonl

Supports filtering by agent, effect, and time range:
  faramesh audit export data/dpr.db --agent payment-bot --since 2024-01-01
  faramesh audit export data/dpr.db --effect DENY --limit 100

Includes chain integrity verification:
  faramesh audit export data/dpr.db --verify`,
	Args: cobra.ExactArgs(1),
	RunE: runAuditExport,
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats <dpr.db>",
	Short: "Show aggregate statistics from the DPR audit trail",
	Args:  cobra.ExactArgs(1),
	RunE:  runAuditStats,
}

var auditShowCmd = &cobra.Command{
	Use:     "show <action-id>",
	Aliases: []string{"get"},
	Short:   "Show evidence for a governed action",
	Args:    cobra.ExactArgs(1),
	RunE:    runAuditShow,
}

var auditTraceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Trace action or approval to linked audit evidence",
	Long: `Trace a governed action or approval to linked DPR evidence without manual API calls.

Examples:
  faramesh audit trace --action-id call_123
	faramesh audit trace --approval-id approval_123
  faramesh audit trace --agent stripe-agent
  faramesh audit trace --run session_abc123`,
	Args: cobra.NoArgs,
	RunE: runAuditTrace,
}

var (
	exportFormat         string
	exportAgent          string
	exportEffect         string
	exportSince          string
	exportLimit          int
	exportVerify         bool
	auditShowDB          string
	auditTraceActionID   string
	auditTraceApprovalID string
	auditTraceAgent      string
	auditTraceRunID      string
	auditTraceTool       string
	auditTraceStatus     string
	auditTraceLimit      int
	auditTraceVisibility string
	auditTraceDB         string
	auditOutputJSON      bool
)

func init() {
	auditExportCmd.Flags().StringVar(&exportFormat, "format", "json", "output format: json, jsonl, csv")
	auditExportCmd.Flags().StringVar(&exportAgent, "agent", "", "filter by agent ID")
	auditExportCmd.Flags().StringVar(&exportEffect, "effect", "", "filter by effect (PERMIT, DENY, DEFER, SHADOW)")
	auditExportCmd.Flags().StringVar(&exportSince, "since", "", "only records after this date (RFC3339 or YYYY-MM-DD)")
	auditExportCmd.Flags().IntVar(&exportLimit, "limit", 10000, "max records to export")
	auditExportCmd.Flags().BoolVar(&exportVerify, "verify", false, "verify chain integrity during export")
	auditShowCmd.Flags().StringVar(&auditShowDB, "db", "", "path to DPR SQLite DB (defaults to current runtime DB)")
	auditShowCmd.Flags().BoolVar(&auditOutputJSON, "json", false, "output raw JSON audit payload")
	auditTraceCmd.Flags().StringVar(&auditTraceActionID, "action-id", "", "visibility action ID to trace")
	auditTraceCmd.Flags().StringVar(&auditTraceApprovalID, "approval-id", "", "approval ID to trace")
	auditTraceCmd.Flags().StringVar(&auditTraceAgent, "agent", "", "agent filter when resolving latest action")
	auditTraceCmd.Flags().StringVar(&auditTraceRunID, "run", "", "run/session filter when resolving latest action")
	auditTraceCmd.Flags().StringVar(&auditTraceTool, "tool", "", "advanced: tool filter when resolving latest action")
	auditTraceCmd.Flags().StringVar(&auditTraceStatus, "status", "", "status filter for action lookup (empty = all)")
	auditTraceCmd.Flags().IntVar(&auditTraceLimit, "limit", 50, "maximum actions to scan when resolving latest action")
	auditTraceCmd.Flags().StringVar(&auditTraceVisibility, "visibility-url", "", "visibility API base URL")
	auditTraceCmd.Flags().StringVar(&auditTraceDB, "db", "", "path to DPR SQLite DB (defaults to current runtime DB)")
	auditTraceCmd.Flags().BoolVar(&auditOutputJSON, "json", false, "output raw JSON audit payload")
	_ = auditTraceCmd.Flags().MarkHidden("tool")

	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditStatsCmd)
	auditCmd.AddCommand(auditShowCmd)
	auditCmd.AddCommand(auditTraceCmd)
}

func runAuditShow(_ *cobra.Command, args []string) error {
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("action id or record id is required")
	}

	visibilityURL := resolveAuditTraceVisibilityURL(auditTraceVisibility)
	actionReq := map[string]any{}
	actionErr := auditTraceHTTPGetJSON(visibilityURL, "/v1/actions/"+url.PathEscape(id), nil, &actionReq)
	if actionErr == nil {
		out := buildAuditTraceOutput(visibilityURL, actionReq, firstNonEmpty(strings.TrimSpace(auditTraceDB), strings.TrimSpace(auditShowDB)))
		emitAuditOutput("Audit Action", out)
		return nil
	}

	dbPath, err := resolveAuditShowDBPath(auditShowDB)
	if err != nil {
		return fmt.Errorf("could not resolve as action id and no DPR DB path available: %w (action lookup: %v)", err, actionErr)
	}

	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	rec, err := store.ByID(id)
	if err != nil {
		return fmt.Errorf("could not resolve %q as action id or record id (action lookup: %v, record lookup: %v)", id, actionErr, err)
	}

	out := map[string]any{
		"db_path":             dbPath,
		"record_id":           rec.RecordID,
		"created_at":          rec.CreatedAt.UTC().Format(time.RFC3339Nano),
		"effect":              rec.Effect,
		"reason_code":         rec.ReasonCode,
		"reason":              rec.Reason,
		"matched_rule_id":     rec.MatchedRuleID,
		"policy_version":      rec.PolicyVersion,
		"agent_id":            rec.AgentID,
		"session_id":          rec.SessionID,
		"tool_id":             rec.ToolID,
		"denial_token":        rec.DenialToken,
		"record_hash":         rec.RecordHash,
		"prev_record_hash":    rec.PrevRecordHash,
		"credential_brokered": rec.CredentialBrokered,
		"credential_source":   rec.CredentialSource,
		"credential_scope":    rec.CredentialScope,
	}

	emitAuditOutput("Audit Record", out)
	return nil
}

func resolveAuditShowDBPath(raw string) (string, error) {
	if explicit := strings.TrimSpace(raw); explicit != "" {
		return explicit, nil
	}

	if state, ok := readCurrentRuntimeStartState(); ok {
		if dataDir := strings.TrimSpace(state.DataDir); dataDir != "" {
			candidate := filepath.Join(dataDir, "faramesh.db")
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}

	fallback := filepath.Join(runtimeStateDirPath(""), "data", "faramesh.db")
	if _, err := os.Stat(fallback); err == nil {
		return fallback, nil
	}

	return "", fmt.Errorf("could not resolve DPR DB path; pass --db (expected runtime default at %s)", fallback)
}

func runAuditTrace(_ *cobra.Command, _ []string) error {
	visibilityURL := resolveAuditTraceVisibilityURL(auditTraceVisibility)
	action, err := resolveAuditTraceAction(visibilityURL)
	if err != nil {
		return err
	}
	out := buildAuditTraceOutput(visibilityURL, action, firstNonEmpty(strings.TrimSpace(auditTraceDB), strings.TrimSpace(auditShowDB)))
	emitAuditOutput("Audit Trace", out)
	return nil
}

func emitAuditOutput(title string, out map[string]any) {
	if auditOutputJSON {
		raw, _ := json.Marshal(out)
		printResponse(title, raw)
		return
	}
	printAuditSummary(title, out)
}

func printAuditSummary(title string, out map[string]any) {
	printHeader(title)

	if action, ok := out["action"].(map[string]any); ok {
		actionID := firstNonEmpty(asTrimmedString(action["id"]), "-")
		agentID := firstNonEmpty(asTrimmedString(action["agent_id"]), "-")
		runID := firstNonEmpty(asTrimmedString(action["run_id"]), "-")
		tool := firstNonEmpty(asTrimmedString(action["tool"]), "-")
		decision := strings.ToUpper(firstNonEmpty(asTrimmedString(action["decision"]), "unknown"))
		status := strings.ToUpper(firstNonEmpty(asTrimmedString(action["status"]), "unknown"))
		approvalID := firstNonEmpty(asTrimmedString(action["approval_id"]), "-")
		recordID := firstNonEmpty(asTrimmedString(action["record_id"]), "-")
		reason := firstNonEmpty(asTrimmedString(action["reason"]), "-")

		fmt.Printf("Action ID:    %s\n", actionID)
		fmt.Printf("Decision:     %s (%s)\n", decision, status)
		fmt.Printf("Agent:        %s\n", agentID)
		fmt.Printf("Run/Session:  %s\n", runID)
		fmt.Printf("Tool:         %s\n", tool)
		fmt.Printf("Approval ID:  %s\n", approvalID)
		fmt.Printf("Record ID:    %s\n", recordID)
		fmt.Printf("Reason:       %s\n", reason)

		if dprRecord, ok := out["dpr_record"].(map[string]any); ok {
			fmt.Println()
			printNoteLine("Tamper-evident DPR linkage")
			fmt.Printf("Rule ID:      %s\n", firstNonEmpty(asTrimmedString(dprRecord["matched_rule_id"]), "-"))
			fmt.Printf("Reason code:  %s\n", firstNonEmpty(asTrimmedString(dprRecord["reason_code"]), "-"))
			fmt.Printf("Record hash:  %s\n", firstNonEmpty(asTrimmedString(dprRecord["record_hash"]), "-"))
			fmt.Printf("Prev hash:    %s\n", firstNonEmpty(asTrimmedString(dprRecord["prev_record_hash"]), "-"))
		}

		if warning := asTrimmedString(out["linkage_warning"]); warning != "" {
			printWarningLine("linkage warning: " + warning)
		}

		if approvalID != "-" {
			printNextStepLine("Approval context: faramesh approvals show " + approvalID)
		}
		if actionID != "-" {
			printNextStepLine("Explain decision: faramesh explain " + actionID)
		}
		printTipLine("Raw payload: add --json")
		return
	}

	if recordID := strings.TrimSpace(fmt.Sprint(out["record_id"])); recordID != "" {
		fmt.Printf("Record ID:    %s\n", recordID)
		fmt.Printf("Effect:       %s\n", firstNonEmpty(strings.TrimSpace(fmt.Sprint(out["effect"])), "-"))
		fmt.Printf("Reason code:  %s\n", firstNonEmpty(strings.TrimSpace(fmt.Sprint(out["reason_code"])), "-"))
		fmt.Printf("Rule ID:      %s\n", firstNonEmpty(strings.TrimSpace(fmt.Sprint(out["matched_rule_id"])), "-"))
		fmt.Printf("Agent:        %s\n", firstNonEmpty(strings.TrimSpace(fmt.Sprint(out["agent_id"])), "-"))
		fmt.Printf("Tool:         %s\n", firstNonEmpty(strings.TrimSpace(fmt.Sprint(out["tool_id"])), "-"))
		fmt.Printf("Record hash:  %s\n", firstNonEmpty(strings.TrimSpace(fmt.Sprint(out["record_hash"])), "-"))
		fmt.Printf("Prev hash:    %s\n", firstNonEmpty(strings.TrimSpace(fmt.Sprint(out["prev_record_hash"])), "-"))
		printTipLine("Raw payload: add --json")
		return
	}

	data, _ := json.Marshal(out)
	printJSON(data)
}

func buildAuditTraceOutput(visibilityURL string, action map[string]any, dbOverride string) map[string]any {
	actionID := firstNonEmpty(
		asTrimmedString(action["id"]),
		asTrimmedString(action["call_id"]),
	)
	agentID := asTrimmedString(action["agent_id"])
	toolID := firstNonEmpty(asTrimmedString(action["tool"]), asTrimmedString(action["tool_id"]))
	status := asTrimmedString(action["status"])
	decision := asTrimmedString(action["decision"])
	runID := actionRunID(action)
	incidentID := firstNonEmpty(
		asTrimmedString(action["incident_id"]),
		nestedMapString(action, "context", "incident_id"),
	)
	approvalID := actionApprovalID(action)
	recordID := firstNonEmpty(
		asTrimmedString(action["record_id"]),
		nestedMapString(action, "context", "record_id"),
	)

	out := map[string]any{
		"visibility_url": visibilityURL,
		"action": map[string]any{
			"id":          actionID,
			"agent_id":    agentID,
			"run_id":      runID,
			"incident_id": incidentID,
			"tool":        toolID,
			"status":      status,
			"decision":    decision,
			"reason":      asTrimmedString(action["reason"]),
			"approval_id": approvalID,
			"record_id":   recordID,
			"created_at":  asTrimmedString(action["created_at"]),
			"updated_at":  asTrimmedString(action["updated_at"]),
		},
	}

	if recordID != "" {
		dbPath, err := resolveAuditShowDBPath(strings.TrimSpace(dbOverride))
		if err != nil {
			out["linkage_warning"] = err.Error()
		} else {
			store, err := dpr.OpenStore(dbPath)
			if err != nil {
				out["linkage_warning"] = fmt.Sprintf("open DPR store: %v", err)
			} else {
				defer store.Close()
				rec, err := store.ByID(recordID)
				if err != nil {
					out["linkage_warning"] = fmt.Sprintf("lookup record_id %q: %v", recordID, err)
				} else {
					// attempt to verify Ed25519 signature when present
					sigValid := false
					if rec.SignatureAlg == "ed25519" && rec.Signature != "" {
						if ok, _ := rec.VerifyEd25519(); ok {
							sigValid = true
						}
					}

					out["dpr_record"] = map[string]any{
						"db_path":                    dbPath,
						"record_id":                  rec.RecordID,
						"canonicalization_algorithm": rec.CanonicalizationAlgorithm,
						"effect":                     rec.Effect,
						"reason_code":                rec.ReasonCode,
						"reason":                     rec.Reason,
						"matched_rule_id":            rec.MatchedRuleID,
						"agent_id":                   rec.AgentID,
						"tool_id":                    rec.ToolID,
						"created_at":                 rec.CreatedAt.UTC().Format(time.RFC3339Nano),
						"record_hash":                rec.RecordHash,
						"signature_algorithm":        rec.SignatureAlg,
						"signature":                  rec.Signature,
						"signer_public_key":          rec.SignerPublicKey,
						"prev_record_hash":           rec.PrevRecordHash,
						"signature_valid":            sigValid,
						"credential_brokered":        rec.CredentialBrokered,
						"credential_source":          rec.CredentialSource,
						"credential_scope":           rec.CredentialScope,
					}
					out["linkage"] = map[string]any{
						"record_id_match":    rec.RecordID == recordID,
						"agent_id_alignment": rec.AgentID == "" || agentID == "" || rec.AgentID == agentID,
						"tool_alignment":     rec.ToolID == "" || toolID == "" || rec.ToolID == toolID,
					}
				}
			}
		}
	} else {
		out["linkage_warning"] = "selected action has no record_id linkage"
	}

	return out
}

func resolveAuditTraceVisibilityURL(raw string) string {
	if explicit := strings.TrimSpace(raw); explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	if state, ok := readCurrentRuntimeStartState(); ok {
		if state.Visibility != nil {
			if base := strings.TrimSpace(state.Visibility.URL); base != "" {
				return strings.TrimRight(base, "/")
			}
		}
	}
	return "http://127.0.0.1:8787"
}

func resolveAuditTraceAction(visibilityURL string) (map[string]any, error) {
	return resolveAuditTraceActionWithSelectors(
		visibilityURL,
		strings.TrimSpace(auditTraceActionID),
		strings.TrimSpace(auditTraceApprovalID),
		strings.TrimSpace(auditTraceAgent),
		strings.TrimSpace(auditTraceRunID),
		strings.TrimSpace(auditTraceTool),
		strings.TrimSpace(auditTraceStatus),
		auditTraceLimit,
	)
}

func resolveAuditTraceActionWithSelectors(visibilityURL, actionID, approvalID, agentID, runID, toolID, status string, limit int) (map[string]any, error) {
	if actionID != "" {
		var out map[string]any
		if err := auditTraceHTTPGetJSON(visibilityURL, "/v1/actions/"+url.PathEscape(actionID), nil, &out); err != nil {
			return nil, err
		}
		return out, nil
	}

	query := map[string]string{
		"limit": fmt.Sprintf("%d", maxInt(limit, 1)),
	}
	if status != "" {
		query["status"] = status
	}
	if agentID != "" {
		query["agent"] = agentID
	}
	if toolID != "" {
		query["tool"] = toolID
	}

	items := make([]map[string]any, 0)
	if err := auditTraceHTTPGetJSON(visibilityURL, "/v1/actions", query, &items); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no matching visibility actions found")
	}

	if approvalID != "" {
		for _, item := range items {
			if actionApprovalID(item) == approvalID {
				return item, nil
			}
		}
		// Some visibility states only surface approval linkage in timeline entries.
		// Retry with a broader status query to find the matching defer token.
		if status != "" {
			fallbackItems := make([]map[string]any, 0)
			fallbackQuery := map[string]string{"limit": fmt.Sprintf("%d", maxInt(limit*4, 200))}
			if agentID != "" {
				fallbackQuery["agent"] = agentID
			}
			if toolID != "" {
				fallbackQuery["tool"] = toolID
			}
			if err := auditTraceHTTPGetJSON(visibilityURL, "/v1/actions", fallbackQuery, &fallbackItems); err == nil {
				for _, item := range fallbackItems {
					if actionApprovalID(item) == approvalID {
						return item, nil
					}
				}
			}
		}
		return nil, fmt.Errorf("approval id not found in latest action set: %s", approvalID)
	}

	if runID != "" {
		for _, item := range items {
			if actionRunID(item) == runID {
				return item, nil
			}
		}
		return nil, fmt.Errorf("run/session id not found in latest action set: %s", runID)
	}

	return items[0], nil
}

func actionRunID(action map[string]any) string {
	return firstNonEmpty(
		asTrimmedString(action["run_id"]),
		asTrimmedString(action["session_id"]),
		nestedMapString(action, "context", "run_id"),
		nestedMapString(action, "context", "session_id"),
	)
}

func actionApprovalID(action map[string]any) string {
	if token := firstNonEmpty(
		asTrimmedString(action["approval_token"]),
		nestedMapString(action, "context", "defer_token"),
	); token != "" {
		return token
	}

	timeline, _ := action["timeline"].([]any)
	for i := len(timeline) - 1; i >= 0; i-- {
		entry, _ := timeline[i].(map[string]any)
		if entry == nil {
			continue
		}
		if token := firstNonEmpty(asTrimmedString(entry["defer_token"]), asTrimmedString(entry["approval_token"])); token != "" {
			return token
		}
	}

	return ""
}

func auditTraceHTTPGetJSON(baseURL, path string, query map[string]string, out any) error {
	endpoint := strings.TrimRight(baseURL, "/") + path
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse visibility URL: %w", err)
	}
	if len(query) > 0 {
		values := u.Query()
		for key, value := range query {
			if strings.TrimSpace(value) == "" {
				continue
			}
			values.Set(key, value)
		}
		u.RawQuery = values.Encode()
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return fmt.Errorf("request visibility API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read visibility response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("visibility API %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode visibility response: %w", err)
	}
	return nil
}

func nestedMapString(root map[string]any, mapKey, valueKey string) string {
	nested, _ := root[mapKey].(map[string]any)
	if nested == nil {
		return ""
	}
	return asTrimmedString(nested[valueKey])
}

func asTrimmedString(v any) string {
	if v == nil {
		return ""
	}
	trimmed := strings.TrimSpace(fmt.Sprint(v))
	if trimmed == "<nil>" || strings.EqualFold(trimmed, "null") {
		return ""
	}
	return trimmed
}

func maxInt(value, floor int) int {
	if value < floor {
		return floor
	}
	return value
}

func runAuditExport(cmd *cobra.Command, args []string) error {
	dbPath := args[0]
	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	var records []*dpr.Record
	if exportAgent != "" {
		records, err = store.RecentByAgent(exportAgent, exportLimit)
	} else {
		records, err = store.Recent(exportLimit)
	}
	if err != nil {
		return fmt.Errorf("read DPR records: %w", err)
	}

	// Apply filters.
	var filtered []*dpr.Record
	var sinceTime time.Time
	if exportSince != "" {
		sinceTime, err = parseTime(exportSince)
		if err != nil {
			return fmt.Errorf("parse --since: %w", err)
		}
	}

	for _, rec := range records {
		if exportEffect != "" && !strings.EqualFold(rec.Effect, exportEffect) {
			continue
		}
		if !sinceTime.IsZero() && rec.CreatedAt.Before(sinceTime) {
			continue
		}
		filtered = append(filtered, rec)
	}

	// Optional chain verification.
	if exportVerify {
		violations := verifyChain(filtered)
		if violations > 0 {
			fmt.Fprintf(os.Stderr, "WARNING: %d chain integrity violations detected\n", violations)
		}
	}

	switch exportFormat {
	case "json":
		return exportJSON(filtered)
	case "jsonl":
		return exportJSONL(filtered)
	case "csv":
		return exportCSV(filtered)
	default:
		return fmt.Errorf("unknown format %q (use json, jsonl, or csv)", exportFormat)
	}
}

func exportJSON(records []*dpr.Record) error {
	out, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func exportJSONL(records []*dpr.Record) error {
	enc := json.NewEncoder(os.Stdout)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

func exportCSV(records []*dpr.Record) error {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	header := []string{
		"record_id", "created_at", "agent_id", "session_id", "tool_id",
		"effect", "matched_rule_id", "reason_code", "reason",
		"policy_version", "intercept_adapter", "record_hash", "prev_record_hash",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, rec := range records {
		row := []string{
			rec.RecordID,
			rec.CreatedAt.UTC().Format(time.RFC3339),
			rec.AgentID,
			rec.SessionID,
			rec.ToolID,
			rec.Effect,
			rec.MatchedRuleID,
			rec.ReasonCode,
			rec.Reason,
			rec.PolicyVersion,
			rec.InterceptAdapter,
			rec.RecordHash,
			rec.PrevRecordHash,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func verifyChain(records []*dpr.Record) int {
	violations := 0
	for _, rec := range records {
		expected := rec.RecordHash
		rec.ComputeHash()
		if rec.RecordHash != expected {
			violations++
		}
		rec.RecordHash = expected // restore
	}
	return violations
}

func parseTime(s string) (time.Time, error) {
	// Try RFC3339 first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Try date-only.
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unsupported time format: %q (use RFC3339 or YYYY-MM-DD)", s)
}

func runAuditStats(cmd *cobra.Command, args []string) error {
	dbPath := args[0]
	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	records, err := store.Recent(100000)
	if err != nil {
		return fmt.Errorf("read records: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	// Compute stats.
	agents := make(map[string]int)
	effects := make(map[string]int)
	rules := make(map[string]int)
	reasonCodes := make(map[string]int)
	tools := make(map[string]int)

	for _, rec := range records {
		agents[rec.AgentID]++
		effects[rec.Effect]++
		if rec.MatchedRuleID != "" {
			rules[rec.MatchedRuleID]++
		}
		reasonCodes[rec.ReasonCode]++
		tools[rec.ToolID]++
	}

	fmt.Println()
	bold.Printf("DPR Audit Statistics — %s\n", dbPath)
	fmt.Printf("  Total records : %d\n", len(records))
	fmt.Printf("  Unique agents : %d\n", len(agents))
	fmt.Printf("  Unique tools  : %d\n", len(tools))
	fmt.Println()

	bold.Println("  Decisions by effect:")
	for _, e := range []string{"PERMIT", "DENY", "DEFER", "SHADOW"} {
		count := effects[e]
		if count == 0 {
			continue
		}
		switch e {
		case "PERMIT":
			green.Printf("    %-8s %d\n", e, count)
		case "DENY":
			red.Printf("    %-8s %d\n", e, count)
		case "DEFER":
			yellow.Printf("    %-8s %d\n", e, count)
		default:
			fmt.Printf("    %-8s %d\n", e, count)
		}
	}

	if len(reasonCodes) > 0 {
		fmt.Println()
		bold.Println("  Top deny reason codes:")
		// Sort by count (simple approach).
		type kv struct {
			k string
			v int
		}
		var sorted []kv
		for k, v := range reasonCodes {
			if k != "" {
				sorted = append(sorted, kv{k, v})
			}
		}
		// Simple bubble sort (small N).
		for i := range sorted {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[j].v > sorted[i].v {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}
		limit := 10
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for _, s := range sorted[:limit] {
			fmt.Printf("    %-35s %d\n", s.k, s.v)
		}
	}

	fmt.Println()
	return nil
}
