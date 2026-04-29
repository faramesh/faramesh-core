package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy lifecycle: validate, test, and inspect policy files",
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate <policy.fpl|policy.yaml>",
	Short: "Validate a policy file (FPL or YAML)",
	Long: `faramesh policy validate parses and validates a policy file.

Supports both FPL (.fpl) and YAML (.yaml) formats.
For FPL files, parses the structured syntax and compiles all rules.
For YAML files, validates rule structure and compiles when-conditions.
Exits 0 on success, 1 on error.

Use this in CI to catch policy errors before deployment:
  faramesh policy validate policies/payment.fpl`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyValidate,
}

var policyInspectCmd = &cobra.Command{
	Use:   "inspect <policy.yaml>",
	Short: "Show compiled policy summary",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyInspect,
}

var policyTestCmd = &cobra.Command{
	Use:   "test <policy.yaml>",
	Short: "Evaluate a tool call against a policy and print the decision",
	Long: `Dry-run a governance decision without a running daemon.

  faramesh policy test policy.yaml --tool stripe/refund --args '{"amount":500}'
  faramesh policy test policy.yaml --tool shell/exec --args '{"cmd":"rm -rf /"}'

Useful for policy authoring, CI, and demos.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyTest,
}

var policyDiffCmd = &cobra.Command{
	Use:   "diff <old.yaml> <new.yaml>",
	Short: "Show rule-level diff between two policy versions",
	Long: `Compare two policy files and show which rules were added, removed, or changed.

  faramesh policy diff policies/v1.yaml policies/v2.yaml

Useful before deploying a policy update.`,
	Args: cobra.ExactArgs(2),
	RunE: runPolicyDiff,
}

var policyReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Signal the running daemon to hot-reload the policy file",
	Long: `Send SIGHUP to the running faramesh daemon, which causes it to re-read
the policy file from disk and atomically swap in the new policy. In-flight
evaluations complete on the old policy; new evaluations use the new policy.

The daemon must be running (faramesh serve). The PID file is read from
$TMPDIR/faramesh/faramesh.pid (or --data-dir if set).

  faramesh policy reload
  faramesh policy reload --data-dir /var/lib/faramesh`,
	RunE: runPolicyReload,
}

var reloadDataDir string

func init() {
	policyReloadCmd.Flags().StringVar(&reloadDataDir, "data-dir", "", "data directory (default: $TMPDIR/faramesh)")
}

var (
	policyTestTool     string
	policyTestArgs     string
	policyTestJSON     bool
	policyValidateJSON bool
)

func init() {
	policyTestCmd.Flags().StringVar(&policyTestTool, "tool", "", "tool ID to test (required)")
	policyTestCmd.Flags().StringVar(&policyTestArgs, "args", "{}", "tool arguments as JSON object")
	policyTestCmd.Flags().BoolVar(&policyTestJSON, "json", false, "output full decision as JSON")
	policyValidateCmd.Flags().BoolVar(&policyValidateJSON, "json", false, "emit machine-readable JSON diagnostics")
	_ = policyTestCmd.MarkFlagRequired("tool")

	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyInspectCmd)
	policyCmd.AddCommand(policyTestCmd)
	policyCmd.AddCommand(policyDiffCmd)
	policyCmd.AddCommand(policyReloadCmd)
}

func runPolicyValidate(cmd *cobra.Command, args []string) error {
	path := args[0]
	report := buildPolicyValidateReport(path)

	if policyValidateJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encode validation report: %w", err)
		}
		if !report.OK {
			return fmt.Errorf("validation failed")
		}
		return nil
	}

	for _, w := range report.Warnings {
		color.Yellow("  ⚠ %s", w)
	}
	if !report.OK {
		for _, e := range report.Errors {
			printError(e)
		}
		return fmt.Errorf("validation failed")
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("✓ ")
	fmt.Printf("%s  ", path)
	if strings.TrimSpace(report.Version) != "" {
		color.New(color.FgHiBlack).Printf("[%s]  ", report.Version)
	}
	fmt.Printf("%d rules  agent=%s", report.RuleCount, report.AgentID)
	if len(report.Warnings) > 0 {
		color.Yellow("  (%d warning(s))", len(report.Warnings))
	}
	fmt.Println()
	return nil
}

type policyValidateReport struct {
	Path      string   `json:"path"`
	Format    string   `json:"format"`
	Version   string   `json:"version,omitempty"`
	AgentID   string   `json:"agent_id,omitempty"`
	RuleCount int      `json:"rule_count"`
	Warnings  []string `json:"warnings,omitempty"`
	Errors    []string `json:"errors,omitempty"`
	OK        bool     `json:"ok"`
}

func buildPolicyValidateReport(path string) policyValidateReport {
	report := policyValidateReport{
		Path:   path,
		Format: "yaml",
	}
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(path)), ".fpl") {
		report.Format = "fpl"
	}

	doc, version, err := policy.LoadFile(path)
	if err != nil {
		report.Errors = []string{"parse error: " + err.Error()}
		report.OK = false
		return report
	}

	report.Version = strings.TrimSpace(version)
	report.AgentID = strings.TrimSpace(doc.AgentID)
	if report.AgentID == "" {
		report.AgentID = "(none)"
	}
	report.RuleCount = len(doc.Rules)

	hardErrors, warnings := splitValidationDiagnostics(policy.Validate(doc))
	report.Warnings = warnings
	report.Errors = hardErrors
	if len(report.Errors) == 0 {
		if _, err := policy.NewEngine(doc, version); err != nil {
			report.Errors = append(report.Errors, "compilation error: "+err.Error())
		}
	}
	report.OK = len(report.Errors) == 0
	return report
}

func splitValidationDiagnostics(diagnostics []string) (errors []string, warnings []string) {
	for _, d := range diagnostics {
		msg := strings.TrimSpace(d)
		if msg == "" {
			continue
		}
		lower := strings.ToLower(msg)
		if strings.HasPrefix(lower, "warning:") {
			warnings = append(warnings, strings.TrimSpace(msg[len("warning:"):]))
			continue
		}
		errors = append(errors, msg)
	}
	return errors, warnings
}

func runPolicyInspect(cmd *cobra.Command, args []string) error {
	path := args[0]
	doc, version, err := policy.LoadFile(path)
	if err != nil {
		return err
	}

	bold := color.New(color.Bold)
	dim := color.New(color.FgHiBlack)

	bold.Printf("Policy: %s\n", path)
	fmt.Printf("  version    : %s\n", version)
	fmt.Printf("  agent-id   : %s\n", doc.AgentID)
	fmt.Printf("  fpl        : %s\n", doc.FarameshVersion)
	fmt.Printf("  rules      : %d\n", len(doc.Rules))
	fmt.Printf("  tools      : %d declared\n", len(doc.Tools))
	fmt.Printf("  default    : %s\n", doc.DefaultEffect)

	if len(doc.Rules) > 0 {
		fmt.Println()
		bold.Println("Rules:")
		for _, r := range doc.Rules {
			effectColor := ruleEffectColor(r.Effect)
			effectColor.Printf("  %-8s", r.Effect)
			fmt.Printf(" %-32s", r.ID)
			if r.Match.Tool != "" {
				dim.Printf("  tool=%s", r.Match.Tool)
			}
			if r.Match.When != "" {
				dim.Printf("  when=%q", truncate(r.Match.When, 40))
			}
			fmt.Println()
		}
	}
	return nil
}

func runPolicyTest(cmd *cobra.Command, args []string) error {
	path := args[0]
	doc, version, err := policy.LoadFile(path)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	// Parse --args JSON.
	var toolArgs map[string]any
	if err := json.Unmarshal([]byte(policyTestArgs), &toolArgs); err != nil {
		return fmt.Errorf("parse --args: %w", err)
	}

	// Build a minimal pipeline (no WAL, no SQLite, no deferrals).
	pip := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	req := core.CanonicalActionRequest{
		CallID:           "policy-test",
		AgentID:          "policy-test-agent",
		SessionID:        "policy-test-session",
		ToolID:           policyTestTool,
		Args:             toolArgs,
		InterceptAdapter: "cli",
	}
	d := pip.Evaluate(req)

	if policyTestJSON {
		out, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	effectColor := ruleEffectColor(string(d.Effect))
	bold := color.New(color.Bold)
	fmt.Println()
	bold.Printf("  Tool:    ")
	fmt.Printf("%s\n", policyTestTool)
	bold.Printf("  Effect:  ")
	effectColor.Printf("%s\n", d.Effect)
	bold.Printf("  Rule:    ")
	fmt.Printf("%s\n", or(d.RuleID, "(default deny)"))
	bold.Printf("  Reason:  ")
	fmt.Printf("%s\n", d.Reason)
	bold.Printf("  Code:    ")
	fmt.Printf("%s\n", d.ReasonCode)
	fmt.Println()
	return nil
}

func runPolicyDiff(cmd *cobra.Command, args []string) error {
	oldDoc, oldVer, err := policy.LoadFile(args[0])
	if err != nil {
		return fmt.Errorf("load %s: %w", args[0], err)
	}
	newDoc, newVer, err := policy.LoadFile(args[1])
	if err != nil {
		return fmt.Errorf("load %s: %w", args[1], err)
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	bold.Printf("Policy diff\n")
	fmt.Printf("  old: %s  [%s]  %d rules\n", args[0], oldVer, len(oldDoc.Rules))
	fmt.Printf("  new: %s  [%s]  %d rules\n", args[1], newVer, len(newDoc.Rules))
	fmt.Println()

	oldByID := make(map[string]policy.Rule)
	for _, r := range oldDoc.Rules {
		oldByID[r.ID] = r
	}
	newByID := make(map[string]policy.Rule)
	for _, r := range newDoc.Rules {
		newByID[r.ID] = r
	}

	changed := false
	for _, r := range newDoc.Rules {
		if old, ok := oldByID[r.ID]; !ok {
			green.Printf("  + %-32s  %s\n", r.ID, r.Effect)
			changed = true
		} else if old.Effect != r.Effect || old.Match.When != r.Match.When || old.Match.Tool != r.Match.Tool {
			yellow.Printf("  ~ %-32s  %s → %s\n", r.ID, old.Effect, r.Effect)
			changed = true
		}
	}
	for _, r := range oldDoc.Rules {
		if _, ok := newByID[r.ID]; !ok {
			red.Printf("  - %-32s  %s\n", r.ID, r.Effect)
			changed = true
		}
	}

	if !changed {
		color.New(color.FgHiBlack).Println("  (no rule changes)")
	}
	fmt.Println()
	return nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func ruleEffectColor(effect string) *color.Color {
	switch effect {
	case "permit", "allow":
		return color.New(color.FgGreen)
	case "deny", "halt":
		return color.New(color.FgRed)
	case "defer", "abstain":
		return color.New(color.FgYellow)
	default:
		return color.New(color.FgHiBlack)
	}
}

func printError(msg string) {
	color.New(color.FgRed, color.Bold).Printf("✗ ")
	fmt.Println(msg)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func runPolicyReload(cmd *cobra.Command, args []string) error {
	dataDir := reloadDataDir
	if dataDir == "" {
		dataDir = filepath.Join(runtimeStateDirPath(""), "data")
	}
	pidPath := filepath.Join(dataDir, "faramesh.pid")
	raw, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no daemon PID file found at %s\nIs the daemon running? Try: faramesh serve --policy policy.yaml", pidPath)
		}
		return fmt.Errorf("read PID file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("invalid PID in %s: %w", pidPath, err)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal daemon (pid %d): %w\nIs faramesh serve still running?", pid, err)
	}
	color.New(color.FgGreen, color.Bold).Printf("✓ ")
	fmt.Printf("Sent SIGHUP to daemon (pid %d) — policy reloading from %s\n",
		pid, sdk.SocketPath)
	return nil
}
