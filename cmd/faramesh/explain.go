package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var (
	explainWALPath    string
	explainPolicyPath string
	explainVisibility string
	explainStatus     string
	explainLimit      int
	explainDB         string
	explainTool       string
	explainJSON       bool
)

type explainResult struct {
	RecordID   string
	Effect     string
	ReasonCode string
	RuleID     string
	RuleMatch  string
	RuleWhen   string
	RuleEffect string
	AgentID    string
	SessionID  string
	ToolID     string
	PolicyVer  string
	CreatedAt  time.Time
}

var explainCmd = &cobra.Command{
	Use:   "explain [action-id]",
	Short: "Explain governed actions, approvals, agents, and runs",
	Long:  "Start with an action ID. Use subcommands to explain by approval, agent, or run/session when action ID is unknown.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runExplainAction,
}

var explainApprovalCmd = &cobra.Command{
	Use:   "approval <approval-id>",
	Short: "Explain governance outcomes for an approval ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplainApproval,
}

var explainAgentCmd = &cobra.Command{
	Use:   "agent <agent-id>",
	Short: "Explain latest governed action for an agent",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplainAgent,
}

var explainRunCmd = &cobra.Command{
	Use:   "run <run-or-session-id>",
	Short: "Explain latest governed action for a run/session",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplainRun,
}

func init() {
	explainCmd.PersistentFlags().StringVar(&explainVisibility, "visibility-url", "", "visibility API base URL")
	explainCmd.PersistentFlags().StringVar(&explainStatus, "status", "", "status filter when resolving latest action (empty = all)")
	explainCmd.PersistentFlags().IntVar(&explainLimit, "limit", 50, "maximum actions to scan for selector-based explain")
	explainCmd.PersistentFlags().StringVar(&explainDB, "db", "", "path to DPR SQLite DB (defaults to current runtime DB)")
	explainCmd.PersistentFlags().BoolVar(&explainJSON, "json", false, "output raw JSON explain payload")
	explainCmd.PersistentFlags().StringVar(&explainTool, "tool", "", "advanced: tool filter for selector-based explain")
	_ = explainCmd.PersistentFlags().MarkHidden("tool")

	explainCmd.Flags().StringVar(&explainWALPath, "wal", "", "path to DPR WAL file")
	explainCmd.Flags().StringVar(&explainPolicyPath, "policy", "", "path to policy YAML file")
	_ = explainCmd.Flags().MarkHidden("wal")
	_ = explainCmd.Flags().MarkHidden("policy")

	explainCmd.AddCommand(explainApprovalCmd)
	explainCmd.AddCommand(explainAgentCmd)
	explainCmd.AddCommand(explainRunCmd)
}

func runExplainAction(_ *cobra.Command, args []string) error {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return fmt.Errorf("action ID is required (or use subcommands: approval|agent|run)")
	}
	actionID := strings.TrimSpace(args[0])
	out, err := buildExplainEntityOutput(actionID, "", "", "")
	if err == nil {
		emitExplainOutput("Explain Action", out)
		return nil
	}

	legacy, legacyErr := runExplainRecordByID(actionID)
	if legacyErr == nil {
		printExplainResult(legacy)
		printWarningLine("record-ID explain is legacy; prefer action ID explain flow")
		return nil
	}

	return wrapExplainResolutionError(err)
}

func runExplainApproval(_ *cobra.Command, args []string) error {
	approvalID := strings.TrimSpace(args[0])
	out, err := buildExplainEntityOutput("", approvalID, "", "")
	if err != nil {
		return wrapExplainResolutionError(err)
	}
	emitExplainOutput("Explain Approval", out)
	return nil
}

func runExplainAgent(_ *cobra.Command, args []string) error {
	agentID := strings.TrimSpace(args[0])
	out, err := buildExplainEntityOutput("", "", agentID, "")
	if err != nil {
		return wrapExplainResolutionError(err)
	}
	emitExplainOutput("Explain Agent", out)
	return nil
}

func runExplainRun(_ *cobra.Command, args []string) error {
	runID := strings.TrimSpace(args[0])
	out, err := buildExplainEntityOutput("", "", "", runID)
	if err != nil {
		return wrapExplainResolutionError(err)
	}
	emitExplainOutput("Explain Run", out)
	return nil
}

func wrapExplainResolutionError(err error) error {
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "request visibility api") || strings.Contains(msg, "connection refused") {
		return fmt.Errorf("explain context is unavailable because the visibility service is not reachable. Start runtime with faramesh up --policy <policy> (or set --visibility-url)")
	}
	if strings.Contains(msg, "no matching visibility actions") {
		return fmt.Errorf("no matching governed action was found for the selector. Try a different action/approval/agent/run ID")
	}
	return err
}

func emitExplainOutput(title string, out map[string]any) {
	if explainJSON {
		raw, _ := json.Marshal(out)
		printResponse(title, raw)
		return
	}
	printExplainSummary(title, out)
}

func printExplainSummary(title string, out map[string]any) {
	printHeader(title)

	action, _ := out["action"].(map[string]any)
	if action == nil {
		data, _ := json.Marshal(out)
		printJSON(data)
		return
	}

	actionID := firstNonEmpty(asTrimmedString(action["id"]), "-")
	approvalID := firstNonEmpty(asTrimmedString(action["approval_id"]), "-")
	agentID := firstNonEmpty(asTrimmedString(action["agent_id"]), "-")
	runID := firstNonEmpty(asTrimmedString(action["run_id"]), "-")
	tool := firstNonEmpty(asTrimmedString(action["tool"]), "-")
	status := strings.ToUpper(firstNonEmpty(asTrimmedString(action["status"]), "unknown"))
	decision := strings.ToUpper(firstNonEmpty(asTrimmedString(action["decision"]), "unknown"))
	reason := firstNonEmpty(asTrimmedString(action["reason"]), "-")
	createdAt := firstNonEmpty(asTrimmedString(action["created_at"]), "-")

	fmt.Printf("Action ID:    %s\n", actionID)
	fmt.Printf("Decision:     %s (%s)\n", decision, status)
	fmt.Printf("Agent:        %s\n", agentID)
	fmt.Printf("Run/Session:  %s\n", runID)
	fmt.Printf("Tool:         %s\n", tool)
	fmt.Printf("Approval ID:  %s\n", approvalID)
	fmt.Printf("Created:      %s\n", createdAt)
	fmt.Printf("Reason:       %s\n", reason)

	if dprRecord, ok := out["dpr_record"].(map[string]any); ok {
		fmt.Println()
		printNoteLine("Linked DPR evidence")
		fmt.Printf("Record ID:    %s\n", firstNonEmpty(asTrimmedString(dprRecord["record_id"]), "-"))
		fmt.Printf("Rule ID:      %s\n", firstNonEmpty(asTrimmedString(dprRecord["matched_rule_id"]), "-"))
		fmt.Printf("Reason code:  %s\n", firstNonEmpty(asTrimmedString(dprRecord["reason_code"]), "-"))
		fmt.Printf("Record hash:  %s\n", firstNonEmpty(asTrimmedString(dprRecord["record_hash"]), "-"))
	}

	if linkageWarning := asTrimmedString(out["linkage_warning"]); linkageWarning != "" {
		printWarningLine("evidence linkage warning: " + linkageWarning)
	}

	if approvalID != "-" {
		printNextStepLine("Inspect approval context: faramesh approvals show " + approvalID)
	}
	if actionID != "-" {
		printNextStepLine("Inspect audit evidence: faramesh audit show " + actionID)
	}
	printTipLine("Raw payload: add --json")
}

func buildExplainEntityOutput(actionID, approvalID, agentID, runID string) (map[string]any, error) {
	visibilityURL := resolveAuditTraceVisibilityURL(explainVisibility)
	action, err := resolveAuditTraceActionWithSelectors(
		visibilityURL,
		actionID,
		approvalID,
		agentID,
		runID,
		strings.TrimSpace(explainTool),
		strings.TrimSpace(explainStatus),
		explainLimit,
	)
	if err != nil {
		return nil, err
	}

	out := buildAuditTraceOutput(visibilityURL, action, firstNonEmpty(strings.TrimSpace(explainDB), strings.TrimSpace(auditShowDB), strings.TrimSpace(auditTraceDB)))
	out["selector"] = map[string]any{
		"action_id":   actionID,
		"approval_id": approvalID,
		"agent_id":    agentID,
		"run_id":      runID,
		"status":      strings.TrimSpace(explainStatus),
		"limit":       maxInt(explainLimit, 1),
	}
	return out, nil
}

func runExplainRecordByID(recordID string) (explainResult, error) {
	walPath, policyPath := resolveExplainInputs(strings.TrimSpace(explainWALPath), strings.TrimSpace(explainPolicyPath))

	if walPath != "" && policyPath != "" {
		result, err := runExplain(recordID, walPath, policyPath)
		if err == nil {
			return result, nil
		}
	}

	dbPath, err := resolveAuditShowDBPath(firstNonEmpty(strings.TrimSpace(explainDB), strings.TrimSpace(auditShowDB)))
	if err != nil {
		if walPath == "" {
			return explainResult{}, fmt.Errorf("explain requires runtime evidence context or explicit --wal/--policy")
		}
		return explainResult{}, err
	}

	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return explainResult{}, fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	rec, err := store.ByID(recordID)
	if err != nil {
		return explainResult{}, fmt.Errorf("lookup record_id %q in %s: %w", recordID, dbPath, err)
	}

	result := explainResult{
		RecordID:   rec.RecordID,
		Effect:     strings.ToUpper(strings.TrimSpace(rec.Effect)),
		ReasonCode: strings.TrimSpace(rec.ReasonCode),
		RuleID:     strings.TrimSpace(rec.MatchedRuleID),
		AgentID:    rec.AgentID,
		SessionID:  rec.SessionID,
		ToolID:     rec.ToolID,
		PolicyVer:  rec.PolicyVersion,
		CreatedAt:  rec.CreatedAt,
	}

	if policyPath != "" {
		doc, _, loadErr := policy.LoadFile(policyPath)
		if loadErr == nil {
			for _, rule := range doc.Rules {
				if strings.TrimSpace(rule.ID) != result.RuleID {
					continue
				}
				result.RuleMatch = strings.TrimSpace(rule.Match.Tool)
				result.RuleWhen = strings.TrimSpace(rule.Match.When)
				result.RuleEffect = strings.TrimSpace(rule.Effect)
				break
			}
		}
	}

	return result, nil
}

func printExplainResult(result explainResult) {
	fmt.Printf("record_id: %s\n", result.RecordID)
	fmt.Printf("effect: %s\n", result.Effect)
	fmt.Printf("reason_code: %s\n", result.ReasonCode)
	fmt.Printf("rule_id: %s\n", result.RuleID)
	fmt.Printf("audit: agent_id=%s session_id=%s tool_id=%s policy_version=%s created_at=%s\n",
		result.AgentID,
		result.SessionID,
		result.ToolID,
		result.PolicyVer,
		result.CreatedAt.UTC().Format(time.RFC3339),
	)
	if result.RuleID != "" {
		fmt.Printf("rule.match.tool: %s\n", result.RuleMatch)
		if strings.TrimSpace(result.RuleWhen) != "" {
			fmt.Printf("rule.match.when: %s\n", result.RuleWhen)
		}
		if strings.TrimSpace(result.RuleEffect) != "" {
			fmt.Printf("rule.effect: %s\n", strings.ToUpper(strings.TrimSpace(result.RuleEffect)))
		}
	}
}

func resolveExplainInputs(rawWAL, rawPolicy string) (string, string) {
	walPath := strings.TrimSpace(rawWAL)
	policyPath := strings.TrimSpace(rawPolicy)

	if walPath == "" {
		if state, ok := readCurrentRuntimeStartState(); ok {
			if dataDir := strings.TrimSpace(state.DataDir); dataDir != "" {
				candidate := filepath.Join(dataDir, "faramesh.wal")
				if _, err := os.Stat(candidate); err == nil {
					walPath = candidate
				}
			}
		}
	}
	if walPath == "" {
		candidate := filepath.Join(runtimeStateDirPath(""), "data", "faramesh.wal")
		if _, err := os.Stat(candidate); err == nil {
			walPath = candidate
		}
	}

	if policyPath == "" {
		if state, ok := readCurrentRuntimeStartState(); ok {
			if p := strings.TrimSpace(state.PolicyPath); p != "" {
				policyPath = p
			}
		}
	}
	if policyPath == "" {
		policyPath = strings.TrimSpace(detectDefaultPolicyPath())
	}

	return walPath, policyPath
}

func runExplain(recordID, walPath, policyPath string) (explainResult, error) {
	recordID = strings.TrimSpace(recordID)
	if recordID == "" {
		return explainResult{}, fmt.Errorf("record id is required")
	}
	if strings.TrimSpace(walPath) == "" {
		return explainResult{}, fmt.Errorf("--wal is required")
	}
	if strings.TrimSpace(policyPath) == "" {
		return explainResult{}, fmt.Errorf("--policy is required")
	}

	records, err := readRecordsFromWAL(walPath)
	if err != nil {
		return explainResult{}, fmt.Errorf("read --wal records: %w", err)
	}
	var rec *dpr.Record
	for _, r := range records {
		if r.RecordID == recordID {
			rec = r
			break
		}
	}
	if rec == nil {
		return explainResult{}, fmt.Errorf("dpr record not found: %s", recordID)
	}

	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		return explainResult{}, fmt.Errorf("load policy: %w", err)
	}
	// Compile to ensure current policy is valid before reconstructing rule details.
	if _, err := policy.NewEngine(doc, rec.PolicyVersion); err != nil {
		return explainResult{}, fmt.Errorf("compile policy: %w", err)
	}

	result := explainResult{
		RecordID:   rec.RecordID,
		Effect:     strings.ToUpper(strings.TrimSpace(rec.Effect)),
		ReasonCode: strings.TrimSpace(rec.ReasonCode),
		RuleID:     strings.TrimSpace(rec.MatchedRuleID),
		AgentID:    rec.AgentID,
		SessionID:  rec.SessionID,
		ToolID:     rec.ToolID,
		PolicyVer:  rec.PolicyVersion,
		CreatedAt:  rec.CreatedAt,
	}
	for _, rule := range doc.Rules {
		if strings.TrimSpace(rule.ID) != result.RuleID {
			continue
		}
		result.RuleMatch = strings.TrimSpace(rule.Match.Tool)
		result.RuleWhen = strings.TrimSpace(rule.Match.When)
		result.RuleEffect = strings.TrimSpace(rule.Effect)
		break
	}
	return result, nil
}
