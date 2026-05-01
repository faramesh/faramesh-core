package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

// Policy suite fixtures (YAML/JSON) — CI-safe batch assertions on policy behavior.
// Schema:
//
//	suite_version: "1"
//	cases:
//	  - id: my-case
//	    tool: stripe/refund
//	    args: {"amount": 100}
//	    expect:
//	      effect: PERMIT
//	      reason_code: RULE_PERMIT   # optional

type policySuiteFile struct {
	SuiteVersion string            `yaml:"suite_version" json:"suite_version"`
	Cases        []policySuiteCase `yaml:"cases" json:"cases"`
}

type policySuiteCase struct {
	ID     string         `yaml:"id" json:"id"`
	Tool   string         `yaml:"tool" json:"tool"`
	Args   map[string]any `yaml:"args" json:"args"`
	Expect struct {
		Effect     string `yaml:"effect" json:"effect"`
		ReasonCode string `yaml:"reason_code" json:"reason_code"`
	} `yaml:"expect" json:"expect"`
}

var (
	policySuiteJSON bool
)

var policySuiteCmd = &cobra.Command{
	Use:   "suite <policy.yaml> --fixtures <suite.yaml>",
	Short: "Run fixture cases against a policy (CI-safe)",
	Long: `Evaluate multiple tool/args pairs against one policy file. Exits 0 if all
expectations match, non-zero on first failure.

  faramesh policy suite policy.yaml --fixtures tests/my_suite.yaml

Fixtures format: suite_version + cases[].id, tool, args, expect.effect, optional expect.reason_code.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicySuite,
}

func init() {
	policySuiteCmd.Flags().StringVar(&policySuiteFixtures, "fixtures", "", "path to YAML or JSON fixture file (required)")
	policySuiteCmd.Flags().BoolVar(&policySuiteJSON, "json", false, "emit machine-readable JSON summary")
	_ = policySuiteCmd.MarkFlagRequired("fixtures")
	policyCmd.AddCommand(policySuiteCmd)
}

var policySuiteFixtures string

func runPolicySuite(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	raw, err := os.ReadFile(policySuiteFixtures)
	if err != nil {
		return fmt.Errorf("read fixtures: %w", err)
	}
	var suite policySuiteFile
	if err := yaml.Unmarshal(raw, &suite); err != nil {
		if jerr := json.Unmarshal(raw, &suite); jerr != nil {
			return fmt.Errorf("parse fixtures (YAML or JSON): yaml: %w; json: %v", err, jerr)
		}
	}
	if len(suite.Cases) == 0 {
		return fmt.Errorf("no cases in fixture file")
	}

	pip := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	type resultRow struct {
		ID       string `json:"id"`
		OK       bool   `json:"ok"`
		Got      string `json:"got_effect"`
		Want     string `json:"want_effect"`
		GotCode  string `json:"got_reason_code,omitempty"`
		WantCode string `json:"want_reason_code,omitempty"`
		Detail   string `json:"detail,omitempty"`
	}
	var rows []resultRow
	failed := 0

	for i, c := range suite.Cases {
		id := c.ID
		if id == "" {
			id = fmt.Sprintf("case-%d", i)
		}
		if c.Tool == "" {
			failed++
			rows = append(rows, resultRow{ID: id, OK: false, Detail: "missing tool"})
			continue
		}
		args := c.Args
		if args == nil {
			args = map[string]any{}
		}
		d := pip.Evaluate(core.CanonicalActionRequest{
			CallID:           "suite-" + id,
			AgentID:          "policy-suite-agent",
			SessionID:        "policy-suite-session",
			ToolID:           c.Tool,
			Args:             args,
			InterceptAdapter: "cli",
		})
		wantFX := strings.ToUpper(strings.TrimSpace(c.Expect.Effect))
		gotFX := strings.ToUpper(string(d.Effect))
		ok := wantFX == gotFX
		gotCode := reasons.Normalize(d.ReasonCode)
		wantCode := strings.TrimSpace(c.Expect.ReasonCode)
		if wantCode != "" && reasons.Normalize(wantCode) != gotCode {
			ok = false
		}
		if !ok {
			failed++
		}
		detail := ""
		if !ok {
			detail = fmt.Sprintf("got effect=%s code=%s", gotFX, gotCode)
		}
		rows = append(rows, resultRow{
			ID: id, OK: ok, Got: gotFX, Want: wantFX,
			GotCode: gotCode, WantCode: wantCode, Detail: detail,
		})
	}

	if policySuiteJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"policy":   policyPath,
			"fixtures": policySuiteFixtures,
			"failed":   failed,
			"total":    len(suite.Cases),
			"results":  rows,
		})
	}

	bold := color.New(color.Bold)
	for _, r := range rows {
		if r.OK {
			color.Green("✓ %s  %s", r.ID, r.Want)
		} else {
			color.Red("✗ %s  want %s  %s", r.ID, r.Want, r.Detail)
		}
	}
	fmt.Println()
	if failed > 0 {
		bold.Printf("policy suite: %d/%d failed\n", failed, len(suite.Cases))
		return fmt.Errorf("%d/%d cases failed", failed, len(suite.Cases))
	}
	bold.Printf("policy suite: all %d cases passed\n", len(suite.Cases))
	return nil
}
