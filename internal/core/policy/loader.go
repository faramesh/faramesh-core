package policy

import (
	"crypto/sha256"
	"fmt"
	"os"

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

// LoadFile reads and parses a policy YAML file.
// Returns the parsed Doc and its SHA256 version hash.
func LoadFile(path string) (*Doc, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read policy file %q: %w", path, err)
	}
	return LoadBytes(data)
}

// LoadBytes parses policy YAML from raw bytes.
func LoadBytes(data []byte) (*Doc, string, error) {
	var doc Doc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("parse policy YAML: %w", err)
	}

	// Compute the version hash from raw bytes so it's stable across reloads
	// of the same content.
	hash := fmt.Sprintf("%x", sha256.Sum256(data))[:16]

	if doc.FarameshVersion == "" {
		doc.FarameshVersion = "1.0"
	}
	if doc.DefaultEffect == "" {
		doc.DefaultEffect = "deny"
	}

	return &doc, hash, nil
}

// Validate checks policy structure and compiles all when-conditions
// without evaluating them. Returns a list of human-readable errors and warnings.
func Validate(doc *Doc) []string {
	var errs []string

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
			if _, err := compileExpr(rule.Match.When, nil); err != nil {
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
