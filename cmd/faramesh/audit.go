package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Inspect governance evidence and verify tamper-evident audit integrity",
}

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Stream live governance decisions",
	Long: `faramesh audit tail connects to the running runtime and streams every
governance decision to the terminal in real time, with color-coded effects.

  faramesh audit tail
  faramesh audit tail --agent payment-bot`,
	RunE: runAuditTail,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify [db-or-wal-path]",
	Short: "Verify tamper-evident audit integrity",
	Long: `Verify audit integrity from the active runtime by default.

Operator workflows may also pass an explicit .wal or .db path.

	faramesh audit verify
  faramesh audit verify /var/lib/faramesh/faramesh.wal
  faramesh audit verify /var/lib/faramesh/faramesh.db`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAuditVerify,
}

var auditCompactCmd = &cobra.Command{
	Use:   "compact <wal-path>",
	Short: "Compact a DPR WAL file and re-verify integrity (advanced)",
	Long: `Rewrites a binary FWAL file in place using the same retention rules as the
daemon (recent record cap + age window). Archives the previous file to a
timestamped .bak sibling, then rewrites retained records with recomputed hash
chains. After compaction, runs full ReplayValidated to prove integrity.

  faramesh audit compact /var/lib/faramesh/faramesh.wal

Only FWAL binary WAL paths are supported (not SQLite .db). Stop the daemon or
copy the WAL elsewhere before compacting the live file.`,
	Args: cobra.ExactArgs(1),
	RunE: runAuditCompact,
}

var auditWalInspectCmd = &cobra.Command{
	Use:   "wal-inspect <wal-path>",
	Short: "Inspect WAL frame versions (advanced)",
	Long: `Walks the WAL without decoding DPR JSON and prints how many frames exist
per header version byte. Use before upgrading WAL readers or when validating
operator backups.

  faramesh audit wal-inspect /var/lib/faramesh/faramesh.wal`,
	Args: cobra.ExactArgs(1),
	RunE: runAuditWalInspect,
}

func runAuditWalInspect(_ *cobra.Command, args []string) error {
	st, err := dpr.ScanWALFrameVersions(args[0])
	if err != nil {
		return err
	}
	color.New(color.FgCyan, color.Bold).Printf("WAL %s\n", st.Path)
	fmt.Printf("file_size_bytes: %d\n", st.FileSize)
	fmt.Printf("total_frames: %d\n", st.TotalFrames)
	if len(st.FramesByVersion) == 0 {
		fmt.Println("frames_by_version: (empty file)")
		return nil
	}
	fmt.Println("frames_by_version:")
	for _, v := range sortedVersionBytes(st.FramesByVersion) {
		fmt.Printf("  version_byte=%d count=%d\n", v, st.FramesByVersion[v])
	}
	return nil
}

func sortedVersionBytes(m map[byte]uint64) []byte {
	var keys []byte
	for k := range m {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

var (
	tailAgent  string
	tailSocket string
)

func init() {
	auditTailCmd.Flags().StringVar(&tailAgent, "agent", "", "filter by agent ID (empty = all agents)")
	auditTailCmd.Flags().StringVar(&tailSocket, "socket", sdk.SocketPath, "daemon Unix socket path")
	_ = auditTailCmd.Flags().MarkHidden("socket")
	auditCompactCmd.Hidden = true
	auditWalInspectCmd.Hidden = true
	auditCmd.AddCommand(auditTailCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	auditCmd.AddCommand(auditCompactCmd)
	auditCmd.AddCommand(auditWalInspectCmd)
}

// runAuditTail connects to the daemon and streams decisions.
// The daemon pushes one JSON line per decision; we color-code and print.
func runAuditTail(cmd *cobra.Command, args []string) error {
	socketPath := strings.TrimSpace(tailSocket)
	if socketFlag := cmd.Flags().Lookup("socket"); socketFlag == nil || !socketFlag.Changed {
		socketPath = resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
	}
	if socketPath == "" {
		socketPath = defaultDaemonSocketPath()
	}

	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect to runtime at %s: %w\n\nIs the runtime running? Try: faramesh up (or faramesh up --policy <path>)", socketPath, err)
	}
	defer conn.Close()

	// Send a subscribe request. The server will stream decisions until disconnect.
	req, _ := json.Marshal(map[string]string{
		"type":     "audit_subscribe",
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
	path := ""
	if len(args) > 0 {
		path = strings.TrimSpace(args[0])
	} else {
		resolved, err := resolveDefaultAuditVerifyPath()
		if err != nil {
			return err
		}
		path = resolved
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("file not found: %s", path)
	}

	printHeader("Audit Integrity Verification")
	printNoteLine("Verifying tamper-evident DPR chain")

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	if isWALFile(path) {
		return verifyWAL(path, bold, green, red)
	}
	return verifyDB(path, bold, green, red)
}

func resolveDefaultAuditVerifyPath() (string, error) {
	state, ok := readCurrentRuntimeStartState()
	if !ok {
		return "", fmt.Errorf("no runtime state found; provide a .wal or .db path")
	}
	dataDir := strings.TrimSpace(state.DataDir)
	if dataDir == "" {
		return "", fmt.Errorf("runtime state does not include a data directory; provide a .wal or .db path")
	}

	candidates := []string{
		filepath.Join(dataDir, "faramesh.wal"),
		filepath.Join(dataDir, "faramesh.db"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no DPR WAL/DB found in %s; provide a .wal or .db path", dataDir)
}

func runAuditCompact(cmd *cobra.Command, args []string) error {
	path := args[0]
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("file not found: %s", path)
	}
	if !isWALFile(path) {
		return fmt.Errorf("compact requires a DPR binary WAL (FWAL-framed records); not recognized: %q", path)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	wal, err := dpr.OpenWAL(path)
	if err != nil {
		return fmt.Errorf("open WAL: %w", err)
	}
	defer wal.Close()

	bold.Printf("\nCompacting WAL: %s\n", path)
	if err := wal.Compact(); err != nil {
		red.Printf("\n✗ compaction failed: %v\n\n", err)
		return err
	}

	n := 0
	if err := wal.ReplayValidated(func(*dpr.Record) error {
		n++
		return nil
	}); err != nil {
		red.Printf("\n✗ post-compaction chain validation failed: %v\n\n", err)
		return fmt.Errorf("post-compaction validation: %w", err)
	}

	green.Printf("\n✓ WAL compacted and chain integrity verified (%d records retained).\n\n", n)
	return nil
}

// walFrameMagicLE matches internal/core/dpr: first 4 bytes of each frame are
// little-endian uint32(0x4657414c) (ASCII "FWAL" interpreted as LE word).
const walFrameMagicLE = uint32(0x4657414c)

func isWALFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := f.Read(hdr[:]); err != nil {
		return false
	}
	return binary.LittleEndian.Uint32(hdr[:]) == walFrameMagicLE
}

func verifyWAL(path string, bold, green, red *color.Color) error {
	wal, err := dpr.OpenWAL(path)
	if err != nil {
		return fmt.Errorf("open WAL: %w", err)
	}
	defer wal.Close()

	bold.Printf("\nVerifying DPR chain integrity (WAL): %s\n", path)
	fmt.Println("Mode: full chain validation (genesis + hash + chain links per agent)")

	count := 0
	err = wal.ReplayValidated(func(rec *dpr.Record) error {
		count++
		return nil
	})

	if err != nil {
		red.Printf("\n✗ CHAIN VIOLATION: %v\n", err)
		fmt.Printf("Records verified before failure: %d\n", count)
		printNextStepLine("Inspect latest evidence: faramesh audit show <action-id>")
		return fmt.Errorf("audit chain verification failed after %d records: %w", count, err)
	}

	green.Printf("\n✓ Chain integrity verified. %d records, 0 violations.\n", count)
	fmt.Println("  Checked: per-frame CRC32, canonical hash, genesis markers, chain links")
	printSuccessLine("Audit integrity verification completed")
	fmt.Println()
	return nil
}

func verifyDB(dbPath string, bold, green, red *color.Color) error {
	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	records, err := store.Recent(10000)
	if err != nil {
		return fmt.Errorf("read records: %w", err)
	}

	bold.Printf("\nVerifying DPR chain integrity (SQLite): %s\n", dbPath)
	fmt.Printf("Mode: per-record hash recomputation (use .wal file for full chain validation)\n")
	fmt.Printf("Records to verify: %d\n\n", len(records))

	violations := 0
	for i, rec := range records {
		expected := rec.RecordHash
		rec.ComputeHash()
		if rec.RecordHash != expected {
			red.Printf("✗ HASH VIOLATION record %d: %s\n", i, rec.RecordID)
			violations++
		}
	}

	if violations == 0 {
		green.Printf("✓ Hash integrity verified. %d records, 0 violations.\n\n", len(records))
		printSuccessLine("Audit integrity verification completed")
	} else {
		red.Printf("✗ %d hash integrity violation(s) detected.\n\n", violations)
		printNextStepLine("Inspect latest evidence: faramesh audit show <action-id>")
		return fmt.Errorf("detected %d hash integrity violation(s)", violations)
	}
	return nil
}
