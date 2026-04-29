package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"gopkg.in/yaml.v3"
)

type suiteDecisionSnapshot struct {
	Effect     string
	ReasonCode string
}

func TestPolicyMigrationEquivalence_SuiteFixtures_YAMLVsDecompiledFPL(t *testing.T) {
	root := findRepoRoot(t)
	yamlPolicyPath := filepath.Join(root, "tests", "policy_suite_policy.yaml")
	suitePath := filepath.Join(root, "tests", "policy_suite_fixtures.yaml")
	fplPolicyPath := writeDecompiledPolicyFixture(t, yamlPolicyPath)

	yamlDecisions := evaluatePolicySuiteDecisions(t, yamlPolicyPath, suitePath)
	fplDecisions := evaluatePolicySuiteDecisions(t, fplPolicyPath, suitePath)

	if len(yamlDecisions) != len(fplDecisions) {
		t.Fatalf("decision counts differ: yaml=%d fpl=%d", len(yamlDecisions), len(fplDecisions))
	}
	for id, want := range yamlDecisions {
		got, ok := fplDecisions[id]
		if !ok {
			t.Fatalf("missing case %q in FPL decision set", id)
		}
		if got != want {
			t.Fatalf("case %q mismatch: yaml=%+v fpl=%+v", id, want, got)
		}
	}
}

func TestPolicyMigrationEquivalence_ReplayWAL_YAMLVsDecompiledFPL(t *testing.T) {
	root := findRepoRoot(t)
	yamlPolicyPath := filepath.Join(root, "tests", "policy_replay_policy.yaml")
	walPath := writeReplayWALFixture(t)
	fplPolicyPath := writeDecompiledPolicyFixture(t, yamlPolicyPath)

	yamlSummary, err := runPolicyReplayWAL(yamlPolicyPath, walPath, 0)
	if err != nil {
		t.Fatalf("replay yaml policy: %v", err)
	}
	fplSummary, err := runPolicyReplayWAL(fplPolicyPath, walPath, 0)
	if err != nil {
		t.Fatalf("replay fpl policy: %v", err)
	}

	if yamlSummary.TotalRecords != fplSummary.TotalRecords || yamlSummary.Divergences != fplSummary.Divergences {
		t.Fatalf("replay summary mismatch: yaml=%+v fpl=%+v", yamlSummary, fplSummary)
	}
	if yamlSummary.TotalRecords == 0 {
		t.Fatalf("replay fixture must include records, got yaml=%+v fpl=%+v", yamlSummary, fplSummary)
	}
	if len(yamlSummary.Samples) != len(fplSummary.Samples) {
		t.Fatalf("replay sample length mismatch: yaml=%d fpl=%d", len(yamlSummary.Samples), len(fplSummary.Samples))
	}
	for i := range yamlSummary.Samples {
		if yamlSummary.Samples[i] != fplSummary.Samples[i] {
			t.Fatalf("replay sample[%d] mismatch: yaml=%+v fpl=%+v", i, yamlSummary.Samples[i], fplSummary.Samples[i])
		}
	}
}

func writeDecompiledPolicyFixture(t *testing.T, policyPath string) string {
	t.Helper()

	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("load policy fixture %q: %v", policyPath, err)
	}
	plan := buildDecompilePlan(doc)
	if len(plan.Warnings) > 0 {
		t.Fatalf("fixture policy %q must decompile losslessly, warnings: %v", policyPath, plan.Warnings)
	}

	source := fpl.DecompileToFPL(
		plan.AgentID,
		plan.DefaultEffect,
		plan.Vars,
		plan.Phases,
		plan.Rules,
		plan.Budget,
		plan.Delegates,
		plan.Ambient,
		plan.Selectors,
	)

	outPath := filepath.Join(t.TempDir(), "roundtrip.fpl")
	if err := os.WriteFile(outPath, []byte(source), 0o600); err != nil {
		t.Fatalf("write temp FPL fixture: %v", err)
	}
	return outPath
}

func evaluatePolicySuiteDecisions(t *testing.T, policyPath, fixturesPath string) map[string]suiteDecisionSnapshot {
	t.Helper()

	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("load policy %q: %v", policyPath, err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("compile policy %q: %v", policyPath, err)
	}

	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		t.Fatalf("read fixtures %q: %v", fixturesPath, err)
	}
	var suite policySuiteFile
	if err := yaml.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("parse suite fixtures %q: %v", fixturesPath, err)
	}
	if len(suite.Cases) == 0 {
		t.Fatalf("fixture suite %q has no cases", fixturesPath)
	}

	pip := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	out := make(map[string]suiteDecisionSnapshot, len(suite.Cases))
	for i, c := range suite.Cases {
		caseID := strings.TrimSpace(c.ID)
		if caseID == "" {
			caseID = "case-" + strings.TrimSpace(c.Tool)
		}
		if strings.TrimSpace(c.Tool) == "" {
			t.Fatalf("suite case[%d] missing tool", i)
		}
		if _, exists := out[caseID]; exists {
			t.Fatalf("duplicate suite case id %q", caseID)
		}

		d := pip.Evaluate(core.CanonicalActionRequest{
			CallID:           "migration-" + caseID,
			AgentID:          "migration-equivalence-agent",
			SessionID:        "migration-equivalence-session",
			ToolID:           c.Tool,
			Args:             c.Args,
			InterceptAdapter: "cli",
		})
		out[caseID] = suiteDecisionSnapshot{
			Effect:     strings.ToUpper(strings.TrimSpace(string(d.Effect))),
			ReasonCode: reasons.Normalize(d.ReasonCode),
		}
	}
	return out
}

func writeReplayWALFixture(t *testing.T) string {
	t.Helper()

	walPath := filepath.Join(t.TempDir(), "policy-replay.wal")
	w, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("open replay wal fixture: %v", err)
	}
	defer func() {
		if err := w.Close(); err != nil {
			t.Fatalf("close replay wal fixture: %v", err)
		}
	}()

	records := []*dpr.Record{
		{
			RecordID:         "migration-replay-1",
			ToolID:           "http/get",
			Effect:           "PERMIT",
			ReasonCode:       "RULE_PERMIT",
			SelectorSnapshot: map[string]any{"endpoint": "https://safe.example"},
			CreatedAt:        time.Date(2026, time.April, 5, 10, 0, 0, 0, time.UTC),
		},
		{
			RecordID:         "migration-replay-2",
			ToolID:           "shell/exec",
			Effect:           "DENY",
			ReasonCode:       "RULE_DENY",
			SelectorSnapshot: map[string]any{"cmd": "echo test"},
			CreatedAt:        time.Date(2026, time.April, 5, 10, 1, 0, 0, time.UTC),
		},
	}

	for _, rec := range records {
		if err := w.Write(rec); err != nil {
			t.Fatalf("write replay wal fixture %q: %v", rec.RecordID, err)
		}
	}

	return walPath
}
