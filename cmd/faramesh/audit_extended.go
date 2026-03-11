package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
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
  faramesh audit export data/dpr.db --format jsonl | jq '.effect'

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

var (
	exportFormat string
	exportAgent  string
	exportEffect string
	exportSince  string
	exportLimit  int
	exportVerify bool
)

func init() {
	auditExportCmd.Flags().StringVar(&exportFormat, "format", "json", "output format: json, jsonl, csv")
	auditExportCmd.Flags().StringVar(&exportAgent, "agent", "", "filter by agent ID")
	auditExportCmd.Flags().StringVar(&exportEffect, "effect", "", "filter by effect (PERMIT, DENY, DEFER, SHADOW)")
	auditExportCmd.Flags().StringVar(&exportSince, "since", "", "only records after this date (RFC3339 or YYYY-MM-DD)")
	auditExportCmd.Flags().IntVar(&exportLimit, "limit", 10000, "max records to export")
	auditExportCmd.Flags().BoolVar(&exportVerify, "verify", false, "verify chain integrity during export")

	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditStatsCmd)
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
