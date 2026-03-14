package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var explainCmd = &cobra.Command{
	Use:   "explain [dpr-record-id]",
	Short: "Explain why a tool call was denied or deferred",
	Long: `Provide a human-readable explanation of why a specific governance decision
was made. Shows the matching rule, evaluated conditions, and contextual
factors that led to the decision.

Example:
  faramesh explain dpr-abc123
  faramesh explain --last       # Explain the most recent decision
  faramesh explain --last-deny  # Explain the most recent denial`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

var (
	explainLast     bool
	explainLastDeny bool
	explainToken    string
	explainJSON     bool
	explainDB       string
	explainDataDir  string
	explainPolicy   string
)

func init() {
	explainCmd.Flags().BoolVar(&explainLast, "last", false, "Explain the most recent decision")
	explainCmd.Flags().BoolVar(&explainLastDeny, "last-deny", false, "Explain the most recent denial")
	explainCmd.Flags().StringVar(&explainToken, "token", "", "Explain by denial token (dnl_...) instead of record ID")
	explainCmd.Flags().BoolVar(&explainJSON, "json", false, "emit explain result as machine-readable JSON")
	explainCmd.Flags().StringVar(&explainDB, "db", "", "path to DPR SQLite database (default: <data-dir>/faramesh.db)")
	explainCmd.Flags().StringVar(&explainDataDir, "data-dir", "", "directory containing faramesh.db (default: $TMPDIR/faramesh)")
	explainCmd.Flags().StringVar(&explainPolicy, "policy", "policy.yaml", "path to policy YAML for rule context")
	rootCmd.AddCommand(explainCmd)
}

func runExplain(_ *cobra.Command, args []string) error {
	if len(args) == 0 && !explainLast && !explainLastDeny && explainToken == "" {
		return fmt.Errorf("specify a DPR record ID, --last, or --last-deny")
	}
	if explainLast && explainLastDeny {
		return fmt.Errorf("--last and --last-deny cannot be used together")
	}

	dbPath := explainDB
	if dbPath == "" {
		dataDir := explainDataDir
		if dataDir == "" {
			dataDir = filepath.Join(os.TempDir(), "faramesh")
		}
		dbPath = filepath.Join(dataDir, "faramesh.db")
	}

	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	var rec *dpr.Record
	if explainLast {
		recs, err := store.Recent(1)
		if err != nil {
			return fmt.Errorf("query latest decision: %w", err)
		}
		if len(recs) == 0 {
			return fmt.Errorf("no DPR records found in %s", dbPath)
		}
		rec = recs[0]
	} else if explainLastDeny {
		recs, err := store.Recent(500)
		if err != nil {
			return fmt.Errorf("query recent decisions: %w", err)
		}
		for _, r := range recs {
			if strings.EqualFold(r.Effect, "DENY") {
				rec = r
				break
			}
		}
		if rec == nil {
			return fmt.Errorf("no DENY records found in %s", dbPath)
		}
	} else if explainToken != "" {
		recs, err := store.Recent(10000)
		if err != nil {
			return fmt.Errorf("query recent decisions: %w", err)
		}
		for _, r := range recs {
			if r.DenialToken == explainToken {
				rec = r
				break
			}
		}
		if rec == nil {
			return fmt.Errorf("no DPR record found for denial token %s", explainToken)
		}
	} else {
		rec, err = store.ByID(args[0])
		if err != nil {
			return fmt.Errorf("lookup DPR record %s: %w", args[0], err)
		}
	}

	var matchedRule *policy.Rule
	if doc, _, err := policy.LoadFile(explainPolicy); err == nil {
		for i := range doc.Rules {
			r := doc.Rules[i]
			if r.ID == rec.MatchedRuleID {
				matchedRule = &r
				break
			}
		}
	}

	if explainJSON {
		matched := map[string]any{}
		if matchedRule != nil {
			matched = map[string]any{
				"id":   matchedRule.ID,
				"tool": matchedRule.Match.Tool,
				"when": matchedRule.Match.When,
			}
		}
		out := map[string]any{
			"record_id":           rec.RecordID,
			"effect":              rec.Effect,
			"rule_id":             rec.MatchedRuleID,
			"reason":              rec.Reason,
			"reason_code":         rec.ReasonCode,
			"denial_token":        rec.DenialToken,
			"agent_id":            rec.AgentID,
			"tool_id":             rec.ToolID,
			"session_id":          rec.SessionID,
			"policy_version":      rec.PolicyVersion,
			"intercept_adapter":   rec.InterceptAdapter,
			"args_structural_sig": rec.ArgsStructuralSig,
			"created_at":          rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			"matched_rule":        matched,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	bold := color.New(color.Bold)
	bold.Printf("Explaining decision: %s\n", rec.RecordID)
	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────┐")
	fmt.Printf("│  Record:    %s\n", rec.RecordID)
	fmt.Printf("│  Effect:    %s\n", rec.Effect)
	fmt.Printf("│  Rule:      %s\n", or(rec.MatchedRuleID, "(none)"))
	fmt.Printf("│  Reason:    %s\n", or(rec.Reason, "(none)"))
	fmt.Printf("│  Code:      %s\n", or(rec.ReasonCode, "(none)"))
	fmt.Printf("│  Token:     %s\n", or(rec.DenialToken, "(none)"))
	fmt.Printf("│  Agent:     %s\n", rec.AgentID)
	fmt.Printf("│  Tool:      %s\n", rec.ToolID)
	fmt.Printf("│  Session:   %s\n", or(rec.SessionID, "(none)"))
	fmt.Printf("│  Time:      %s\n", rec.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"))
	fmt.Println("│")
	fmt.Println("│  Conditions evaluated:")
	if matchedRule != nil {
		if matchedRule.Match.Tool != "" {
			fmt.Printf("│    tool == %s\n", matchedRule.Match.Tool)
		}
		if matchedRule.Match.When != "" {
			fmt.Printf("│    when: %s\n", matchedRule.Match.When)
		}
		if matchedRule.Match.Tool == "" && matchedRule.Match.When == "" {
			fmt.Println("│    (no explicit conditions)")
		}
	} else {
		fmt.Println("│    (rule not found in current policy file)")
	}
	fmt.Println("│")
	fmt.Println("│  Context factors:")
	fmt.Printf("│    policy_version=%s\n", or(rec.PolicyVersion, "(none)"))
	fmt.Printf("│    intercept_adapter=%s\n", or(rec.InterceptAdapter, "(none)"))
	fmt.Printf("│    args_structural_sig=%s\n", or(rec.ArgsStructuralSig, "(none)"))
	fmt.Println("└─────────────────────────────────────────────────────┘")
	fmt.Println()

	return nil
}
