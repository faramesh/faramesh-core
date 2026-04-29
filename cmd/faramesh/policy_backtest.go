package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const defaultPolicyBacktestYAML = `
faramesh-version: "1.0"
agent-id: "p8-backtest"
default_effect: deny
rules:
  - id: permit-safe-http
    match:
      tool: "http/get"
      when: "args.endpoint == 'https://safe.example'"
    effect: permit
    reason: "safe endpoint"
    reason_code: RULE_PERMIT
  - id: deny-shell
    match:
      tool: "shell/exec"
    effect: deny
    reason: "shell execution denied"
    reason_code: RULE_DENY
`

type policyBacktestFixture struct {
	Name               string         `json:"name"`
	ToolID             string         `json:"tool_id"`
	Args               map[string]any `json:"args"`
	ExpectedEffect     string         `json:"expected_effect"`
	ExpectedReasonCode string         `json:"expected_reason_code"`
}

type policyBacktestFailure struct {
	Name               string `json:"name"`
	ExpectedEffect     string `json:"expected_effect"`
	ActualEffect       string `json:"actual_effect"`
	ExpectedReasonCode string `json:"expected_reason_code"`
	ActualReasonCode   string `json:"actual_reason_code"`
}

type policyBacktestReport struct {
	Total    int                    `json:"total"`
	Passed   int                    `json:"passed"`
	Failed   int                    `json:"failed"`
	Failures []policyBacktestFailure `json:"failures,omitempty"`
}

var (
	policyBacktestPolicyPath   string
	policyBacktestFixturesPath string
)

var policyBacktestCmd = &cobra.Command{
	Use:   "backtest",
	Short: "Replay deterministic policy fixtures and fail on regressions",
	Long: `Run deterministic backtest fixtures against policy evaluation.
The command exits non-zero if any fixture's expected effect or reason_code
regresses.

Examples:
  faramesh policy backtest
  faramesh policy backtest --policy policy.yaml --fixtures tests/policy_backtest.json`,
	RunE: runPolicyBacktest,
}

func init() {
	policyBacktestCmd.Flags().StringVar(&policyBacktestPolicyPath, "policy", "", "optional policy YAML path (default built-in backtest policy)")
	policyBacktestCmd.Flags().StringVar(&policyBacktestFixturesPath, "fixtures", "", "optional backtest fixtures JSON path")
	policyCmd.AddCommand(policyBacktestCmd)
}

func runPolicyBacktest(cmd *cobra.Command, _ []string) error {
	policyBytes, err := loadBacktestPolicyBytes(policyBacktestPolicyPath)
	if err != nil {
		return err
	}
	fixtures, err := loadBacktestFixtures(policyBacktestFixturesPath)
	if err != nil {
		return err
	}

	report, err := runPolicyBacktestFixtures(policyBytes, fixtures)
	if err != nil {
		return err
	}

	fmt.Printf("policy backtest: %d total, %d passed, %d failed\n", report.Total, report.Passed, report.Failed)
	if report.Failed > 0 {
		for _, f := range report.Failures {
			fmt.Printf("- %s: effect expected=%s actual=%s; reason_code expected=%s actual=%s\n",
				f.Name, f.ExpectedEffect, f.ActualEffect, f.ExpectedReasonCode, f.ActualReasonCode)
		}
		return fmt.Errorf("policy backtest failed with %d regression(s)", report.Failed)
	}
	return nil
}

func runPolicyBacktestFixtures(policyBytes []byte, fixtures []policyBacktestFixture) (policyBacktestReport, error) {
	doc, version, err := policy.LoadBytes(policyBytes)
	if err != nil {
		return policyBacktestReport{}, fmt.Errorf("load backtest policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return policyBacktestReport{}, fmt.Errorf("compile backtest policy: %w", err)
	}
	pip := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	sorted := append([]policyBacktestFixture(nil), fixtures...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	report := policyBacktestReport{Total: len(sorted)}
	for i, fx := range sorted {
		callID := fmt.Sprintf("policy-backtest-%03d", i+1)
		decision := pip.Evaluate(core.CanonicalActionRequest{
			CallID:           callID,
			AgentID:          "policy-backtest-agent",
			SessionID:        "policy-backtest-session",
			ToolID:           fx.ToolID,
			Args:             fx.Args,
			InterceptAdapter: "cli",
		})
		actualEffect := strings.ToUpper(string(decision.Effect))
		expectedEffect := strings.ToUpper(strings.TrimSpace(fx.ExpectedEffect))
		actualCode := strings.TrimSpace(decision.ReasonCode)
		expectedCode := strings.TrimSpace(fx.ExpectedReasonCode)
		if actualEffect == expectedEffect && actualCode == expectedCode {
			report.Passed++
			continue
		}
		report.Failures = append(report.Failures, policyBacktestFailure{
			Name:               fx.Name,
			ExpectedEffect:     expectedEffect,
			ActualEffect:       actualEffect,
			ExpectedReasonCode: expectedCode,
			ActualReasonCode:   actualCode,
		})
	}
	report.Failed = len(report.Failures)
	return report, nil
}

func loadBacktestPolicyBytes(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return []byte(defaultPolicyBacktestYAML), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --policy file: %w", err)
	}
	return b, nil
}

func loadBacktestFixtures(path string) ([]policyBacktestFixture, error) {
	if strings.TrimSpace(path) == "" {
		return defaultPolicyBacktestFixtures(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --fixtures file: %w", err)
	}
	var fixtures []policyBacktestFixture
	if err := json.Unmarshal(b, &fixtures); err != nil {
		return nil, fmt.Errorf("decode --fixtures JSON: %w", err)
	}
	return fixtures, nil
}

func defaultPolicyBacktestFixtures() []policyBacktestFixture {
	return []policyBacktestFixture{
		{
			Name:               "permit-safe-http",
			ToolID:             "http/get",
			Args:               map[string]any{"endpoint": "https://safe.example"},
			ExpectedEffect:     "PERMIT",
			ExpectedReasonCode: "RULE_PERMIT",
		},
		{
			Name:               "deny-shell-exec",
			ToolID:             "shell/exec",
			Args:               map[string]any{"cmd": "echo hello"},
			ExpectedEffect:     "DENY",
			ExpectedReasonCode: "RULE_DENY",
		},
	}
}
