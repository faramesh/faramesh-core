package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit operations: live tail, verify, and explain DPR records",
}

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Stream live governance decisions from a running daemon",
	Long: `faramesh audit tail connects to the running daemon and streams every
governance decision to the terminal in real time, with color-coded effects.

  faramesh audit tail
  faramesh audit tail --agent payment-bot`,
	RunE: runAuditTail,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify <db-path>",
	Short: "Verify the SHA256 chain integrity of a DPR SQLite store",
	Args:  cobra.ExactArgs(1),
	RunE:  runAuditVerify,
}

var (
	tailAgent  string
	tailSocket string
)

func init() {
	auditTailCmd.Flags().StringVar(&tailAgent, "agent", "", "filter by agent ID (empty = all agents)")
	auditTailCmd.Flags().StringVar(&tailSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	auditCmd.AddCommand(auditTailCmd)
	auditCmd.AddCommand(auditVerifyCmd)
}

// runAuditTail connects to the daemon and streams decisions.
// The daemon pushes one JSON line per decision; we color-code and print.
func runAuditTail(cmd *cobra.Command, args []string) error {
	conn, err := net.DialTimeout("unix", tailSocket, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect to daemon at %s: %w\n\nIs the daemon running? Try: faramesh serve --policy policy.yaml", tailSocket, err)
	}
	defer conn.Close()

	// Send a tail subscription request.
	req, _ := json.Marshal(map[string]string{
		"type":     "audit_tail",
		"agent_id": tailAgent,
	})
	req = append(req, '\n')
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("send tail request: %w", err)
	}

	bold := color.New(color.Bold)
	dim := color.New(color.FgHiBlack)
	permitColor := color.New(color.FgGreen, color.Bold)
	denyColor := color.New(color.FgRed, color.Bold)
	deferColor := color.New(color.FgYellow, color.Bold)

	fmt.Println()
	bold.Println("Faramesh Audit Tail — streaming decisions (Ctrl+C to stop)")
	fmt.Println()

	dec := json.NewDecoder(conn)
	for {
		var event map[string]any
		if err := dec.Decode(&event); err != nil {
			return fmt.Errorf("stream ended: %w", err)
		}

		effect, _ := event["effect"].(string)
		toolID, _ := event["tool_id"].(string)
		agentID, _ := event["agent_id"].(string)
		ruleID, _ := event["rule_id"].(string)
		latencyMs, _ := event["latency_ms"].(float64)

		ts := time.Now().Format("15:04:05")

		switch effect {
		case "PERMIT":
			permitColor.Printf("[%s] PERMIT  ", ts)
		case "DENY":
			denyColor.Printf("[%s] DENY    ", ts)
		case "DEFER":
			deferColor.Printf("[%s] DEFER   ", ts)
		default:
			dim.Printf("[%s] %-8s", ts, effect)
		}

		fmt.Printf("%-22s %-16s", padRight(toolID, 22), agentID)

		if ruleID != "" {
			dim.Printf("  rule=%s", ruleID)
		}
		if latencyMs > 0 {
			dim.Printf("  %dms", int(latencyMs))
		}
		fmt.Println()
	}
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	dbPath := args[0]
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("database not found: %s", dbPath)
	}

	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	records, err := store.Recent(10000)
	if err != nil {
		return fmt.Errorf("read records: %w", err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	bold.Printf("\nVerifying DPR chain integrity: %s\n", dbPath)
	fmt.Printf("Records to verify: %d\n\n", len(records))

	violations := 0
	for i, rec := range records {
		expected := rec.RecordHash
		rec.ComputeHash()
		if rec.RecordHash != expected {
			red.Printf("✗ CHAIN VIOLATION record %d: %s\n", i, rec.RecordID)
			violations++
		}
	}

	if violations == 0 {
		green.Printf("✓ Chain integrity verified. %d records, 0 violations.\n\n", len(records))
	} else {
		red.Printf("✗ %d chain integrity violation(s) detected.\n\n", violations)
		os.Exit(1)
	}
	return nil
}
