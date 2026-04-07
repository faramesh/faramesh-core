package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewritePythonOffboardNeutralizesLangchainInstall(t *testing.T) {
	src := strings.Join([]string{
		"from faramesh.adapters.langchain import install_langchain_interceptor",
		"patched = install_langchain_interceptor(",
		"    policy=\"policy.fpl\",",
		"    agent_id=\"a1\",",
		")",
		"print(patched)",
	}, "\n")

	next, rules, removed, changed := rewritePythonOffboard(src)
	if !changed {
		t.Fatal("expected python offboard rewrite to change source")
	}
	if removed < 2 {
		t.Fatalf("expected multiple removed lines, got %d", removed)
	}
	if strings.Contains(next, "from faramesh") {
		t.Fatalf("expected faramesh import removed, got:\n%s", next)
	}
	if !strings.Contains(next, "patched = {}") {
		t.Fatalf("expected interceptor install assignment neutralized, got:\n%s", next)
	}
	if !containsRule(rules, "neutralize_install_langchain_interceptor") {
		t.Fatalf("expected neutralize rule in %v", rules)
	}
}

func TestRewritePythonOffboardUnwrapsGovernWrapper(t *testing.T) {
	src := strings.Join([]string{
		"from faramesh import govern",
		"governed_tool = govern(",
		"    my_tool,",
		"    policy=\"policy.fpl\",",
		")",
	}, "\n")

	next, rules, _, changed := rewritePythonOffboard(src)
	if !changed {
		t.Fatal("expected govern wrapper to be rewritten")
	}
	if strings.Contains(next, "from faramesh") {
		t.Fatalf("expected faramesh import removed, got:\n%s", next)
	}
	if !strings.Contains(next, "governed_tool = my_tool") {
		t.Fatalf("expected govern wrapper unwrapped, got:\n%s", next)
	}
	if !containsRule(rules, "unwrap_govern_wrapper") {
		t.Fatalf("expected unwrap rule in %v", rules)
	}
}

func TestRewritePythonOffboardHandlesAliasedInstallCalls(t *testing.T) {
	src := strings.Join([]string{
		"import faramesh.adapters.langchain as lc",
		"patched = lc.install_langchain_interceptor(policy=\"policy.fpl\", agent_id=\"a1\")",
	}, "\n")

	next, rules, _, changed := rewritePythonOffboard(src)
	if !changed {
		t.Fatal("expected aliased install call to be rewritten")
	}
	if strings.Contains(next, "install_langchain_interceptor") {
		t.Fatalf("expected install call removed, got:\n%s", next)
	}
	if !strings.Contains(next, "patched = {}") {
		t.Fatalf("expected install assignment neutralized, got:\n%s", next)
	}
	if !containsRule(rules, "neutralize_install_langchain_interceptor") {
		t.Fatalf("expected neutralize_install_langchain_interceptor in %v", rules)
	}
}

func TestRewritePythonOffboardHandlesAliasedGovernCalls(t *testing.T) {
	src := strings.Join([]string{
		"import faramesh as fm",
		"governed_tool = fm.govern(my_tool, policy=\"policy.fpl\")",
	}, "\n")

	next, rules, _, changed := rewritePythonOffboard(src)
	if !changed {
		t.Fatal("expected aliased govern call to be rewritten")
	}
	if !strings.Contains(next, "governed_tool = my_tool") {
		t.Fatalf("expected govern wrapper unwrapped, got:\n%s", next)
	}
	if !containsRule(rules, "unwrap_govern_wrapper") {
		t.Fatalf("expected unwrap_govern_wrapper in %v", rules)
	}
}

func TestRewritePythonOffboardRemovesPythonFarameshEnvAssignments(t *testing.T) {
	src := strings.Join([]string{
		"import os",
		"os.environ[\"FARAMESH_SOCKET\"] = \"/tmp/f.sock\"",
		"os.environ.setdefault('FARAMESH_AGENT_ID', 'agent-1')",
		"os.putenv(\"FARAMESH_AUTOLOAD\", \"1\")",
		"print(\"ok\")",
	}, "\n")

	next, rules, removed, changed := rewritePythonOffboard(src)
	if !changed {
		t.Fatal("expected python env assignment removal")
	}
	if removed < 3 {
		t.Fatalf("expected at least 3 removed lines, got %d", removed)
	}
	if strings.Contains(next, "FARAMESH_SOCKET") || strings.Contains(next, "FARAMESH_AGENT_ID") || strings.Contains(next, "FARAMESH_AUTOLOAD") {
		t.Fatalf("expected faramesh python env assignments removed, got:\n%s", next)
	}
	if !containsRule(rules, "remove_faramesh_python_env") {
		t.Fatalf("expected remove_faramesh_python_env in %v", rules)
	}
}

func TestRewritePythonOffboardPreservesNonFarameshImports(t *testing.T) {
	src := "import os, faramesh.autopatch as ap, sys"
	next, rules, _, changed := rewritePythonOffboard(src)
	if !changed {
		t.Fatal("expected mixed import rewrite")
	}
	if next != "import os, sys" {
		t.Fatalf("expected preserved non-faramesh imports, got: %s", next)
	}
	if !containsRule(rules, "remove_faramesh_import") {
		t.Fatalf("expected remove_faramesh_import in %v", rules)
	}
}

func TestRewritePythonOffboardLeavesValidIndentedNoop(t *testing.T) {
	src := strings.Join([]string{
		"if enabled:",
		"    import faramesh.autopatch as autopatch",
		"    autopatch.install()",
		"    do_work()",
	}, "\n")

	next, _, _, changed := rewritePythonOffboard(src)
	if !changed {
		t.Fatal("expected indented faramesh statements to be rewritten")
	}
	if !strings.Contains(next, "pass  # faramesh offboard") {
		t.Fatalf("expected pass noops for indented removals, got:\n%s", next)
	}
	if strings.Contains(next, "autopatch.install") {
		t.Fatalf("expected autopatch install call removed, got:\n%s", next)
	}
}

func TestRewriteShellOffboardStripsFarameshEnvPrefix(t *testing.T) {
	src := strings.Join([]string{
		"#!/usr/bin/env bash",
		"export FARAMESH_AUTOLOAD=1",
		"FARAMESH_SOCKET=/tmp/f.sock FARAMESH_AGENT_ID=a1 python agent.py",
		"echo done",
	}, "\n")

	next, rules, _, changed := rewriteShellOffboard(src)
	if !changed {
		t.Fatal("expected shell rewrite to change source")
	}
	if strings.Contains(next, "FARAMESH_AUTOLOAD") || strings.Contains(next, "FARAMESH_SOCKET") {
		t.Fatalf("expected faramesh env assignments removed, got:\n%s", next)
	}
	if !strings.Contains(next, "python agent.py") {
		t.Fatalf("expected command preserved after prefix stripping, got:\n%s", next)
	}
	if !containsRule(rules, "remove_faramesh_export") {
		t.Fatalf("expected export removal rule in %v", rules)
	}
	if !containsRule(rules, "strip_faramesh_prefix_assignments") {
		t.Fatalf("expected prefix strip rule in %v", rules)
	}
}

func TestRewriteShellOffboardRemovesUnset(t *testing.T) {
	src := strings.Join([]string{
		"unset FARAMESH_SOCKET FARAMESH_AGENT_ID",
		"echo done",
	}, "\n")
	next, rules, _, changed := rewriteShellOffboard(src)
	if !changed {
		t.Fatal("expected shell unset rewrite")
	}
	if strings.Contains(next, "unset FARAMESH_") {
		t.Fatalf("expected faramesh unset removed, got:\n%s", next)
	}
	if !containsRule(rules, "remove_faramesh_unset") {
		t.Fatalf("expected remove_faramesh_unset rule in %v", rules)
	}
}

func TestRewriteShellOffboardStripsNodeOptionsAutopatch(t *testing.T) {
	src := strings.Join([]string{
		"#!/usr/bin/env bash",
		"export NODE_OPTIONS=\"--require @faramesh/sdk/autopatch\"",
		"NODE_OPTIONS=\"--require @faramesh/sdk/autopatch\" node server.js",
		"echo done",
	}, "\n")

	next, rules, _, changed := rewriteShellOffboard(src)
	if !changed {
		t.Fatal("expected node options rewrite to change source")
	}
	if strings.Contains(next, "@faramesh/sdk/autopatch") {
		t.Fatalf("expected node autopatch references removed, got:\n%s", next)
	}
	if !strings.Contains(next, "node server.js") {
		t.Fatalf("expected command preserved after NODE_OPTIONS strip, got:\n%s", next)
	}
	if !containsRule(rules, "remove_faramesh_node_options_export") {
		t.Fatalf("expected remove_faramesh_node_options_export in %v", rules)
	}
	if !containsRule(rules, "strip_faramesh_node_options_prefix") {
		t.Fatalf("expected strip_faramesh_node_options_prefix in %v", rules)
	}
}

func TestRewriteJSOffboardNeutralizesAutopatchAndGovern(t *testing.T) {
	src := strings.Join([]string{
		"import { installAutoPatch } from '@faramesh/sdk/autopatch';",
		"const { govern } = require('@faramesh/sdk/govern');",
		"process.env.FARAMESH_AUTOLOAD = '1';",
		"const patched = installAutoPatch(server);",
		"const decision = await govern({ toolId: 'http/get', args: {} });",
		"installAutoPatch(otherServer);",
	}, "\n")

	next, rules, removed, changed := rewriteJSOffboard(src)
	if !changed {
		t.Fatal("expected JS offboard rewrite to change source")
	}
	if removed < 5 {
		t.Fatalf("expected multiple removed lines, got %d", removed)
	}
	if strings.Contains(next, "@faramesh/sdk/") {
		t.Fatalf("expected faramesh imports removed, got:\n%s", next)
	}
	if strings.Contains(next, "FARAMESH_AUTOLOAD") {
		t.Fatalf("expected faramesh env assignment removed, got:\n%s", next)
	}
	if !strings.Contains(next, "const patched = false;") {
		t.Fatalf("expected installAutoPatch assignment neutralized, got:\n%s", next)
	}
	if !strings.Contains(next, `const decision = { effect: "PERMIT" };`) {
		t.Fatalf("expected govern assignment neutralized, got:\n%s", next)
	}
	if strings.Contains(next, "installAutoPatch(otherServer)") {
		t.Fatalf("expected standalone installAutoPatch call removed, got:\n%s", next)
	}
	if !containsRule(rules, "remove_faramesh_js_import") {
		t.Fatalf("expected remove_faramesh_js_import in %v", rules)
	}
	if !containsRule(rules, "neutralize_js_install_autopatch") {
		t.Fatalf("expected neutralize_js_install_autopatch in %v", rules)
	}
	if !containsRule(rules, "neutralize_js_govern_call") {
		t.Fatalf("expected neutralize_js_govern_call in %v", rules)
	}
}

func TestOffboardProjectDryRunAndApplyWithBackups(t *testing.T) {
	root := t.TempDir()
	agentPath := filepath.Join(root, "agent.py")
	src := strings.Join([]string{
		"from faramesh.adapters.langchain import install_langchain_interceptor",
		"install_langchain_interceptor(policy=\"policy.fpl\")",
		"print('ok')",
	}, "\n")
	if err := os.WriteFile(agentPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write agent: %v", err)
	}

	dry, err := offboardProject(root, offboardOptions{Apply: false, BackupExt: ".bak"})
	if err != nil {
		t.Fatalf("dry-run offboard: %v", err)
	}
	if dry.FilesChanged != 1 {
		t.Fatalf("expected one changed file in dry-run, got %d", dry.FilesChanged)
	}
	rawAfterDry, err := os.ReadFile(agentPath)
	if err != nil {
		t.Fatalf("read after dry-run: %v", err)
	}
	if string(rawAfterDry) != src {
		t.Fatalf("dry-run should not modify file, got:\n%s", rawAfterDry)
	}

	applied, err := offboardProject(root, offboardOptions{Apply: true, BackupExt: ".bak"})
	if err != nil {
		t.Fatalf("apply offboard: %v", err)
	}
	if applied.FilesChanged != 1 {
		t.Fatalf("expected one changed file in apply mode, got %d", applied.FilesChanged)
	}

	updated, err := os.ReadFile(agentPath)
	if err != nil {
		t.Fatalf("read updated file: %v", err)
	}
	if strings.Contains(string(updated), "from faramesh") || strings.Contains(string(updated), "install_langchain_interceptor") {
		t.Fatalf("expected faramesh wiring removed, got:\n%s", updated)
	}

	if _, err := os.Stat(agentPath + ".bak"); err != nil {
		t.Fatalf("expected backup file, stat error: %v", err)
	}
}

func TestOffboardProjectApplyIsIdempotent(t *testing.T) {
	root := t.TempDir()
	scriptPath := filepath.Join(root, "start.sh")
	src := strings.Join([]string{
		"#!/usr/bin/env bash",
		"export FARAMESH_AUTOLOAD=1",
		"FARAMESH_SOCKET=/tmp/f.sock python agent.py",
	}, "\n")
	if err := os.WriteFile(scriptPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	first, err := offboardProject(root, offboardOptions{Apply: true, BackupExt: ".bak"})
	if err != nil {
		t.Fatalf("first offboard apply: %v", err)
	}
	if first.FilesChanged != 1 {
		t.Fatalf("expected first apply to change one file, got %d", first.FilesChanged)
	}

	second, err := offboardProject(root, offboardOptions{Apply: true, BackupExt: ".bak"})
	if err != nil {
		t.Fatalf("second offboard apply should be idempotent, got err: %v", err)
	}
	if second.FilesChanged != 0 {
		t.Fatalf("expected second apply idempotent with zero changes, got %d", second.FilesChanged)
	}
}

func TestOffboardRoundTripMatrixOnboardOffboardOnboard(t *testing.T) {
	type rewriteFn func(string) (string, []string, int, bool)

	testCases := []struct {
		name      string
		rewrite   rewriteFn
		onboarded string
		reOnboard string
		forbidden []string
	}{
		{
			name:    "python_langchain",
			rewrite: rewritePythonOffboard,
			onboarded: strings.Join([]string{
				"from faramesh.adapters.langchain import install_langchain_interceptor",
				"from faramesh import govern",
				"patched = install_langchain_interceptor(policy='policy.fpl', agent_id='a1')",
				"decision = govern(tool_call, policy='policy.fpl')",
				"print(patched, decision)",
			}, "\n"),
			reOnboard: strings.Join([]string{
				"from faramesh import govern",
				"decision = govern(tool_call, policy='policy.fpl')",
			}, "\n"),
			forbidden: []string{"from faramesh", "install_langchain_interceptor", "govern("},
		},
		{
			name:    "shell_runtime_env",
			rewrite: rewriteShellOffboard,
			onboarded: strings.Join([]string{
				"#!/usr/bin/env bash",
				"export FARAMESH_AUTOLOAD=1",
				"FARAMESH_SOCKET=/tmp/f.sock FARAMESH_AGENT_ID=agent-a python agent.py",
				"echo done",
			}, "\n"),
			reOnboard: strings.Join([]string{
				"export FARAMESH_AUTOLOAD=1",
				"FARAMESH_SOCKET=/tmp/f.sock python agent.py",
			}, "\n"),
			forbidden: []string{"FARAMESH_", "@faramesh/sdk/autopatch"},
		},
		{
			name:    "js_sdk_wiring",
			rewrite: rewriteJSOffboard,
			onboarded: strings.Join([]string{
				"import { installAutoPatch } from '@faramesh/sdk/autopatch';",
				"const { govern } = require('@faramesh/sdk/govern');",
				"process.env.FARAMESH_AGENT_ID = 'agent-a';",
				"const patched = installAutoPatch(server);",
				"const decision = await govern({ toolId: 'http/get' });",
			}, "\n"),
			reOnboard: strings.Join([]string{
				"import { installAutoPatch } from '@faramesh/sdk/autopatch';",
				"const patchedAgain = installAutoPatch(server);",
			}, "\n"),
			forbidden: []string{"@faramesh/sdk/", "FARAMESH_", "installAutoPatch(", "govern("},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			first, _, _, changed := tc.rewrite(tc.onboarded)
			if !changed {
				t.Fatalf("expected first offboard rewrite to change source for %s", tc.name)
			}
			assertNoForbiddenSubstrings(t, first, tc.forbidden)

			roundTripInput := strings.TrimSpace(first + "\n" + tc.reOnboard)
			second, _, _, changedRoundTrip := tc.rewrite(roundTripInput)
			if !changedRoundTrip {
				t.Fatalf("expected offboard rewrite to clean re-onboarded source for %s", tc.name)
			}
			assertNoForbiddenSubstrings(t, second, tc.forbidden)

			stable, _, _, changedStable := tc.rewrite(second)
			if changedStable {
				t.Fatalf("expected stable offboard output on third pass for %s", tc.name)
			}
			if stable != second {
				t.Fatalf("expected stable output after round-trip cleanup for %s", tc.name)
			}
		})
	}
}

func TestOffboardRemoveGeneratedPolicies(t *testing.T) {
	root := t.TempDir()
	generatedDir := filepath.Join(root, "faramesh")
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		t.Fatalf("mkdir generated dir: %v", err)
	}
	p1 := filepath.Join(generatedDir, "policy.yaml")
	p2 := filepath.Join(generatedDir, "policy.fpl")
	if err := os.WriteFile(p1, []byte("x"), 0o600); err != nil {
		t.Fatalf("write policy yaml: %v", err)
	}
	if err := os.WriteFile(p2, []byte("x"), 0o600); err != nil {
		t.Fatalf("write policy fpl: %v", err)
	}

	report, err := offboardProject(root, offboardOptions{Apply: true, BackupExt: ".bak", RemoveGenerated: true})
	if err != nil {
		t.Fatalf("offboard with remove-generated: %v", err)
	}
	if len(report.RemovedPaths) != 2 {
		t.Fatalf("expected 2 removed generated paths, got %d (%v)", len(report.RemovedPaths), report.RemovedPaths)
	}
	if _, err := os.Stat(p1); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed", p1)
	}
	if _, err := os.Stat(p2); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed", p2)
	}
}

func TestRootIncludesOffboardCommand(t *testing.T) {
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "offboard" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected offboard command to be registered on root command")
	}
}

func containsRule(rules []string, target string) bool {
	for _, r := range rules {
		if r == target {
			return true
		}
	}
	return false
}

func assertNoForbiddenSubstrings(t *testing.T, src string, forbidden []string) {
	t.Helper()
	for _, marker := range forbidden {
		if strings.Contains(src, marker) {
			t.Fatalf("unexpected marker %q in rewritten source:\n%s", marker, src)
		}
	}
}
