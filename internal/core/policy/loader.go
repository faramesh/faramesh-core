package policy

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"gopkg.in/yaml.v3"
)

// syntheticToolIDs is a broad set of representative tool IDs used to test
// whether one glob pattern shadows another during overlap analysis.
// A pattern A shadows B if every tool that matches B also matches A, and A
// appears before B in the rule list.
var syntheticProbeIDs = []string{
	"http/get", "http/post", "http/put", "http/delete", "http/patch",
	"shell/exec", "shell/run", "shell/bash",
	"stripe/refund", "stripe/charge", "stripe/customer",
	"file/read", "file/write", "file/delete",
	"db/query", "db/insert", "db/update", "db/delete",
	"email/send", "slack/post",
	"aws/s3/put", "aws/lambda/invoke",
	"read_file", "write_file", "delete_file",
	"search", "browse", "summarize",
}

// loadPolicyDocument parses YAML, merges FPL (see mergeFPLIntoDoc), and returns the doc,
// a 16-char version id (SHA-256 prefix of raw YAML || FPL digest), and the full 64-char hex hash.
// policyDir is the directory containing the policy file; use "" for inline/URL/string loads
// (fpl_files is rejected when policyDir is empty).
func loadPolicyDocument(data []byte, policyDir string) (*Doc, string, string, error) {
	doc, err := parsePolicyYAML(data)
	if err != nil {
		return nil, "", "", err
	}
	if policyDir == "" && len(doc.FPLFiles) > 0 {
		return nil, "", "", fmt.Errorf("policy: fpl_files requires LoadFile (paths are relative to the YAML file)")
	}
	fplDigest, err := mergeFPLIntoDoc(doc, policyDir)
	if err != nil {
		return nil, "", "", err
	}
	combined := append(append([]byte{}, data...), fplDigest...)
	h := sha256.Sum256(combined)
	full := fmt.Sprintf("%x", h)
	return doc, full[:16], full, nil
}

// LoadFile reads and parses a policy file (YAML or FPL).
// Returns the parsed Doc and its SHA256 version hash.
func LoadFile(path string) (*Doc, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read policy file %q: %w", path, err)
	}
	if strings.HasSuffix(path, ".fpl") {
		return loadFPLDocument(data)
	}
	doc, ver, _, err := loadPolicyDocument(data, filepath.Dir(path))
	return doc, ver, err
}

// loadFPLDocument parses a standalone .fpl file into a Doc.
func loadFPLDocument(data []byte) (*Doc, string, error) {
	fplDoc, err := fpl.ParseDocument(string(data))
	if err != nil {
		return nil, "", fmt.Errorf("parse FPL: %w", err)
	}
	doc := fplDocToPolicy(fplDoc)

	h := sha256.Sum256(data)
	full := fmt.Sprintf("%x", h)
	return doc, full[:16], nil
}

// fplDocToPolicy converts a parsed fpl.Document into a policy.Doc.
func fplDocToPolicy(fplDoc *fpl.Document) *Doc {
	doc := &Doc{
		FarameshVersion: "1.0",
		DefaultEffect:   "deny",
	}

	if len(fplDoc.Agents) > 0 {
		ag := fplDoc.Agents[0]
		doc.AgentID = ag.ID
		if ag.Default != "" {
			doc.DefaultEffect = ag.Default
		}

		if len(ag.Vars) > 0 {
			doc.Vars = make(map[string]any, len(ag.Vars))
			for k, v := range ag.Vars {
				doc.Vars[k] = v
			}
		}

		if len(ag.Budgets) > 0 {
			b := ag.Budgets[0]
			doc.Budget = &Budget{
				DailyUSD:   b.Daily,
				SessionUSD: b.Max,
				MaxCalls:   b.MaxCalls,
				OnExceed:   b.OnExceed,
			}
		}

		if len(ag.Phases) > 0 {
			doc.Phases = make(map[string]Phase, len(ag.Phases))
			for _, ph := range ag.Phases {
				doc.Phases[ph.ID] = Phase{
					Tools:    ph.Tools,
					Duration: ph.Duration,
					Next:     ph.Next,
				}
			}
		}

		if len(ag.Credentials) > 0 {
			if doc.Tools == nil {
				doc.Tools = make(map[string]Tool)
			}
			for _, cred := range ag.Credentials {
				if cred == nil {
					continue
				}
				tags := []string{"credential:broker", "credential:required"}
				if scope := strings.TrimSpace(cred.MaxScope); scope != "" {
					tags = append(tags, "credential:scope:"+scope)
				}
				for _, target := range cred.Scope {
					toolID := strings.TrimSpace(target)
					if toolID == "" {
						continue
					}
					entry := doc.Tools[toolID]
					entry.Tags = appendUniqueStrings(entry.Tags, tags...)
					doc.Tools[toolID] = entry
				}
			}
		}

		for i, r := range ag.Rules {
			doc.Rules = append(doc.Rules, fplRuleToRule(r, i))
		}
		for _, ph := range ag.Phases {
			for i, r := range ph.Rules {
				doc.Rules = append(doc.Rules, fplRuleToRule(r, len(doc.Rules)+i))
			}
		}
	}

	for i, r := range fplDoc.FlatRules {
		doc.Rules = append(doc.Rules, fplRuleToRule(r, len(doc.Rules)+i))
	}

	if len(fplDoc.Topo) > 0 {
		_ = mergeOrchestratorManifestFromFPL(doc, fplDoc.Topo)
	}

	return doc
}

func fplRuleToRule(r *fpl.Rule, seq int) Rule {
	effect := r.Effect
	strict := false
	if effect == "deny!" {
		effect = "deny"
		strict = true
	}
	switch effect {
	case "allow", "approve":
		effect = "permit"
	case "block", "reject":
		effect = "deny"
	}

	when := strings.TrimSpace(r.Condition)
	if when == "" {
		when = "true"
	}

	reason := strings.TrimSpace(r.Reason)
	reasonCode := ""
	if strict {
		reasonCode = "FPL_STRICT_DENY"
		if reason == "" {
			reason = "strict deny"
		}
	}

	return Rule{
		ID:         fmt.Sprintf("fpl-%d", seq),
		Match:      Match{Tool: r.Tool, When: when},
		Effect:     effect,
		Reason:     reason,
		ReasonCode: reasonCode,
	}
}

func appendUniqueStrings(existing []string, values ...string) []string {
	if len(values) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(values))
	out := make([]string, 0, len(existing)+len(values))
	for _, raw := range existing {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// LoadBytes parses policy YAML from raw bytes.
// If the document sets fpl_files, use LoadFile instead (relative paths need a policy directory).
func LoadBytes(data []byte) (*Doc, string, error) {
	doc, ver, _, err := loadPolicyDocument(data, "")
	return doc, ver, err
}

func parsePolicyYAML(data []byte) (*Doc, error) {
	var doc Doc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}
	if doc.FarameshVersion == "" {
		doc.FarameshVersion = "1.0"
	}
	if doc.DefaultEffect == "" {
		doc.DefaultEffect = "deny"
	}
	return &doc, nil
}

// Validate checks policy structure and compiles all when-conditions
// without evaluating them. Returns a list of human-readable errors and warnings.
func Validate(doc *Doc) []string {
	var errs []string

	if doc.DefaultEffect != "" {
		effect := strings.ToLower(doc.DefaultEffect)
		if effect != "deny" && effect != "permit" && effect != "halt" && effect != "shadow" {
			errs = append(errs, fmt.Sprintf("invalid default_effect: %q (must be deny|permit|halt|shadow)", doc.DefaultEffect))
		}
	}

	// Structural checks.
	seenIDs := make(map[string]int)
	for i, rule := range doc.Rules {
		if rule.ID == "" {
			errs = append(errs, fmt.Sprintf("rule[%d]: missing id", i))
		} else if prev, dup := seenIDs[rule.ID]; dup {
			errs = append(errs, fmt.Sprintf("rule %q at index %d: duplicate id (first seen at index %d)", rule.ID, i, prev))
		} else {
			seenIDs[rule.ID] = i
		}

		effect := rule.Effect
		if effect != "permit" && effect != "deny" && effect != "defer" && effect != "shadow" {
			errs = append(errs, fmt.Sprintf("rule %q: unknown effect %q (must be permit|deny|defer|shadow)", rule.ID, effect))
		}
		if rule.Match.When != "" {
			if _, err := compileExpr(rule.Match.When, evalEnv(doc, nil)); err != nil {
				errs = append(errs, fmt.Sprintf("rule %q: invalid when expression: %v", rule.ID, err))
			}
		}
	}

	// Glob overlap / unreachable rule detection.
	// For each rule R at index i, check whether any earlier rule at index j < i
	// shadows R: i.e., the earlier rule's tool pattern matches every tool that
	// R's pattern matches, and neither rule has a when: condition that could
	// differentiate them.
	//
	// This catches the common mistake:
	//   - match: { tool: "stripe/*" }  → permit   ← shadows all of stripe
	//   - match: { tool: "stripe/refund" } → defer  ← UNREACHABLE
	errs = append(errs, detectGlobOverlap(doc.Rules)...)

	return errs
}

// ValidationErrorsOnly returns only hard validation errors and excludes
// warning-prefixed advisory messages.
func ValidationErrorsOnly(issues []string) []string {
	out := make([]string, 0, len(issues))
	for _, issue := range issues {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(issue)), "warning:") {
			continue
		}
		out = append(out, issue)
	}
	return out
}

// detectGlobOverlap checks for rules that are unreachable because an earlier
// rule with a broader glob pattern always matches first. It uses a set of
// representative tool probe IDs to test pattern coverage.
func detectGlobOverlap(rules []Rule) []string {
	var warnings []string

	for i := 1; i < len(rules); i++ {
		ruleI := rules[i]
		if ruleI.Match.Tool == "" || ruleI.Match.Tool == "*" {
			continue // skip catch-all rules (they're intentionally last)
		}
		if ruleI.Match.When != "" {
			continue // when: conditions create differentiation, can't statically shadow
		}

		// Find all probes that match rule i's tool pattern.
		matchedByI := probesMatching(ruleI.Match.Tool)
		if len(matchedByI) == 0 {
			continue // no known probes match this pattern, skip
		}

		// Check each earlier rule j to see if it shadows all probes matched by i.
		for j := 0; j < i; j++ {
			ruleJ := rules[j]
			if ruleJ.Match.When != "" {
				continue // when: condition means it may not always fire, not a shadow
			}
			matchedByJ := probesMatching(ruleJ.Match.Tool)
			if len(matchedByJ) == 0 {
				continue
			}

			// Rule j shadows rule i if every probe matched by i is also matched by j.
			allShadowed := true
			for _, probe := range matchedByI {
				shadowed := false
				for _, jProbe := range matchedByJ {
					if jProbe == probe {
						shadowed = true
						break
					}
				}
				if !shadowed {
					allShadowed = false
					break
				}
			}

			if allShadowed {
				warnings = append(warnings, fmt.Sprintf(
					"warning: rule %q (index %d, tool=%q) may be unreachable: "+
						"earlier rule %q (index %d, tool=%q) matches all the same tools",
					ruleI.ID, i, ruleI.Match.Tool,
					ruleJ.ID, j, ruleJ.Match.Tool,
				))
				break // only report once per shadowed rule
			}
		}
	}
	return warnings
}

// probesMatching returns the subset of syntheticProbeIDs that match the given tool pattern.
func probesMatching(toolPattern string) []string {
	if toolPattern == "" || toolPattern == "*" {
		return syntheticProbeIDs
	}
	var matched []string
	for _, probe := range syntheticProbeIDs {
		if matchTool(toolPattern, probe) {
			matched = append(matched, probe)
		}
	}
	return matched
}
