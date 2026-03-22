package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var (
	explainWALPath    string
	explainPolicyPath string
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
	Use:   "explain <record-id>",
	Short: "Explain a DPR decision by record ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplainCommand,
}

func init() {
	explainCmd.Flags().StringVar(&explainWALPath, "wal", "", "path to DPR WAL file")
	explainCmd.Flags().StringVar(&explainPolicyPath, "policy", "", "path to policy YAML file")
	_ = explainCmd.MarkFlagRequired("wal")
	_ = explainCmd.MarkFlagRequired("policy")
}

func runExplainCommand(cmd *cobra.Command, args []string) error {
	result, err := runExplain(args[0], explainWALPath, explainPolicyPath)
	if err != nil {
		return err
	}

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
	return nil
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
