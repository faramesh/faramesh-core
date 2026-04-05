package policy

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	if err := validateRuntimeLowerableFPLDocument(fplDoc); err != nil {
		return nil, "", err
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

	if len(fplDoc.Systems) > 0 {
		sys := fplDoc.Systems[0]
		if v := strings.TrimSpace(sys.Version); v != "" {
			doc.FarameshVersion = v
		}
		if sys.MaxOutputBytes > 0 {
			doc.MaxOutputBytes = sys.MaxOutputBytes
		}
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
		if strings.TrimSpace(ag.Model) != "" {
			if doc.Vars == nil {
				doc.Vars = make(map[string]any)
			}
			doc.Vars["agent.model"] = strings.TrimSpace(ag.Model)
			doc.Vars["model_name"] = strings.TrimSpace(ag.Model)
		}
		if strings.TrimSpace(ag.Framework) != "" {
			if doc.Vars == nil {
				doc.Vars = make(map[string]any)
			}
			doc.Vars["agent.framework"] = strings.TrimSpace(ag.Framework)
		}
		if strings.TrimSpace(ag.Version) != "" {
			if doc.Vars == nil {
				doc.Vars = make(map[string]any)
			}
			doc.Vars["agent.version"] = strings.TrimSpace(ag.Version)
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

		if len(ag.Selectors) > 0 {
			for _, sel := range ag.Selectors {
				if sel == nil {
					continue
				}
				doc.ContextGuards = append(doc.ContextGuards, lowerSelectorToContextGuard(sel))
			}
		}

		if len(ag.Ambients) > 0 {
			for _, ambient := range ag.Ambients {
				if ambient == nil {
					continue
				}
				doc.CrossSessionGuards = append(doc.CrossSessionGuards, lowerAmbientToCrossSessionGuards(ambient)...)
			}
		}

		if len(ag.Delegates) > 0 {
			mergeDelegateManifest(doc, ag)
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
				if backend := strings.TrimSpace(cred.Backend); backend != "" {
					tags = append(tags, "credential:backend:"+backend)
				}
				if path := strings.TrimSpace(cred.Path); path != "" {
					tags = append(tags, "credential:path:"+path)
				}
				if ttl := strings.TrimSpace(cred.TTL); ttl != "" {
					tags = append(tags, "credential:ttl:"+ttl)
				}
				if scope := strings.TrimSpace(cred.MaxScope); scope != "" {
					tags = append(tags, "credential:scope:"+scope)
				}
				for _, target := range cred.Scope {
					toolID := strings.TrimSpace(target)
					if toolID == "" {
						continue
					}
					resolved := []string{toolID}
					if !strings.Contains(toolID, "/") {
						base := strings.TrimSpace(cred.ID)
						if base != "" {
							resolved = append(resolved, base+"/"+toolID)
						}
					}
					for _, id := range resolved {
						entry := doc.Tools[id]
						entry.Tags = appendUniqueStrings(entry.Tags, tags...)
						doc.Tools[id] = entry
					}
				}
			}
		}

		for i, r := range ag.Rules {
			doc.Rules = append(doc.Rules, fplRuleToRule(r, i))
		}
		seq := len(doc.Rules)
		for _, ph := range ag.Phases {
			for _, r := range ph.Rules {
				doc.Rules = append(doc.Rules, fplRuleToRule(r, seq))
				seq++
			}
		}
	}

	seq := len(doc.Rules)
	for _, r := range fplDoc.FlatRules {
		doc.Rules = append(doc.Rules, fplRuleToRule(r, seq))
		seq++
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
		Notify:     strings.TrimSpace(r.Notify),
		Reason:     reason,
		ReasonCode: reasonCode,
	}
}

func validateRuntimeLowerableFPLDocument(fplDoc *fpl.Document) error {
	if fplDoc == nil {
		return fmt.Errorf("parse FPL: empty document")
	}
	if len(fplDoc.Agents) > 1 {
		return fmt.Errorf("parse FPL: multi-agent documents are not runtime-loadable yet (found %d agents)", len(fplDoc.Agents))
	}
	if len(fplDoc.Systems) > 1 {
		return fmt.Errorf("parse FPL: multiple system blocks are not supported (found %d)", len(fplDoc.Systems))
	}
	if len(fplDoc.Systems) == 1 {
		sys := fplDoc.Systems[0]
		if onLoad := strings.TrimSpace(sys.OnPolicyLoadFailure); onLoad != "" {
			v := strings.ToLower(onLoad)
			if v != "deny_all" && v != "deny" {
				return fmt.Errorf("parse FPL: system.on_policy_load_failure=%q is unsupported (supported: deny_all)", onLoad)
			}
		}
		if ks := strings.TrimSpace(sys.KillSwitchDefault); ks != "" {
			return fmt.Errorf("parse FPL: system.kill_switch_default=%q is unsupported by runtime loader", ks)
		}
		if sys.MaxOutputBytes < 0 {
			return fmt.Errorf("parse FPL: system.max_output_bytes must be >= 0")
		}
	}
	if len(fplDoc.Agents) == 1 {
		ag := fplDoc.Agents[0]
		if len(ag.Budgets) > 1 {
			return fmt.Errorf("parse FPL: multiple budget blocks are not runtime-loadable yet (found %d)", len(ag.Budgets))
		}
		for _, delegate := range ag.Delegates {
			if delegate == nil {
				continue
			}
			if strings.TrimSpace(delegate.TargetAgent) == "" {
				return fmt.Errorf("parse FPL: delegate block requires a target agent")
			}
			if scope := strings.TrimSpace(delegate.Scope); scope != "" {
				if delegateToolPattern(scope) == "" {
					return fmt.Errorf("parse FPL: delegate %q has invalid scope %q", strings.TrimSpace(delegate.TargetAgent), scope)
				}
			}
			if ttl := strings.TrimSpace(delegate.TTL); ttl != "" {
				if _, err := time.ParseDuration(ttl); err != nil {
					return fmt.Errorf("parse FPL: delegate %q ttl %q is invalid: %w", strings.TrimSpace(delegate.TargetAgent), ttl, err)
				}
			}
			if ceiling := strings.ToLower(strings.TrimSpace(delegate.Ceiling)); ceiling != "" && ceiling != "inherited" && ceiling != "approval" {
				return fmt.Errorf("parse FPL: delegate %q ceiling %q is unsupported (supported: inherited|approval)", strings.TrimSpace(delegate.TargetAgent), strings.TrimSpace(delegate.Ceiling))
			}
		}
		for _, ambient := range ag.Ambients {
			if ambient == nil {
				continue
			}
			if _, err := normalizeGuardEffect(ambient.OnExceed, "ambient.on_exceed"); err != nil {
				return err
			}
			for key, raw := range ambient.Limits {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "max_customers_per_day", "max_calls_per_day":
					if _, err := parsePositiveIntLimit(raw); err != nil {
						return fmt.Errorf("parse FPL: ambient %s=%q is invalid: %w", key, raw, err)
					}
				case "max_data_volume":
					if _, err := parseByteSizeLimit(raw); err != nil {
						return fmt.Errorf("parse FPL: ambient %s=%q is invalid: %w", key, raw, err)
					}
				default:
					return fmt.Errorf("parse FPL: ambient limit %q is unsupported (supported: max_customers_per_day|max_calls_per_day|max_data_volume)", strings.TrimSpace(key))
				}
			}
		}
		for _, sel := range ag.Selectors {
			if sel == nil {
				continue
			}
			if strings.TrimSpace(sel.ID) == "" {
				return fmt.Errorf("parse FPL: selector block requires an id")
			}
			if strings.TrimSpace(sel.Source) == "" {
				return fmt.Errorf("parse FPL: selector %q requires source", strings.TrimSpace(sel.ID))
			}
			if cache := strings.TrimSpace(sel.Cache); cache != "" {
				if _, err := time.ParseDuration(cache); err != nil {
					return fmt.Errorf("parse FPL: selector %q cache %q is invalid: %w", strings.TrimSpace(sel.ID), cache, err)
				}
			}
			if _, err := normalizeGuardEffect(sel.OnUnavailable, "selector.on_unavailable"); err != nil {
				return err
			}
			if _, err := normalizeGuardEffect(sel.OnTimeout, "selector.on_timeout"); err != nil {
				return err
			}
		}
		for _, cred := range ag.Credentials {
			if cred == nil {
				continue
			}
			if len(cred.Scope) == 0 {
				return fmt.Errorf("parse FPL: credential %q requires at least one scope target", strings.TrimSpace(cred.ID))
			}
		}
	}
	return nil
}

func lowerSelectorToContextGuard(sel *fpl.SelectorBlock) ContextGuard {
	maxAgeSecs := 0
	if cache := strings.TrimSpace(sel.Cache); cache != "" {
		if d, err := time.ParseDuration(cache); err == nil && d > 0 {
			maxAgeSecs = int(d / time.Second)
		}
	}
	onMissing, _ := normalizeGuardEffect(sel.OnUnavailable, "selector.on_unavailable")
	onStale, _ := normalizeGuardEffect(sel.OnTimeout, "selector.on_timeout")
	if onMissing == "" {
		onMissing = "deny"
	}
	if onStale == "" {
		onStale = onMissing
	}
	source := strings.TrimSpace(sel.ID)
	if source == "" {
		source = strings.TrimSpace(sel.Source)
	}
	return ContextGuard{
		Source:         source,
		Endpoint:       strings.TrimSpace(sel.Source),
		MaxAgeSecs:     maxAgeSecs,
		OnMissing:      onMissing,
		OnStale:        onStale,
		OnInconsistent: onMissing,
	}
}

func lowerAmbientToCrossSessionGuards(ambient *fpl.AmbientBlock) []CrossSessionGuard {
	if ambient == nil || len(ambient.Limits) == 0 {
		return nil
	}
	onExceed, _ := normalizeGuardEffect(ambient.OnExceed, "ambient.on_exceed")
	if onExceed == "" {
		onExceed = "deny"
	}
	out := make([]CrossSessionGuard, 0, len(ambient.Limits))
	for rawKey, rawValue := range ambient.Limits {
		key := strings.ToLower(strings.TrimSpace(rawKey))
		switch key {
		case "max_customers_per_day":
			limit, err := parsePositiveIntLimit(rawValue)
			if err != nil {
				continue
			}
			out = append(out, CrossSessionGuard{
				Scope:            "principal",
				ToolPattern:      "*",
				Metric:           "unique_record_count",
				Window:           "24h",
				MaxUniqueRecords: limit,
				OnExceed:         onExceed,
				Reason:           "ambient max_customers_per_day limit exceeded",
			})
		case "max_calls_per_day":
			limit, err := parsePositiveIntLimit(rawValue)
			if err != nil {
				continue
			}
			out = append(out, CrossSessionGuard{
				Scope:            "principal",
				ToolPattern:      "*",
				Metric:           "call_count",
				Window:           "24h",
				MaxUniqueRecords: limit,
				OnExceed:         onExceed,
				Reason:           "ambient max_calls_per_day limit exceeded",
			})
		case "max_data_volume":
			limit, err := parseByteSizeLimit(rawValue)
			if err != nil {
				continue
			}
			out = append(out, CrossSessionGuard{
				Scope:            "principal",
				ToolPattern:      "*",
				Metric:           "data_volume_bytes",
				Window:           "24h",
				MaxUniqueRecords: limit,
				OnExceed:         onExceed,
				Reason:           "ambient max_data_volume limit exceeded",
			})
		}
	}
	return out
}

func mergeDelegateManifest(doc *Doc, ag *fpl.AgentBlock) {
	if doc == nil || ag == nil || len(ag.Delegates) == 0 {
		return
	}
	if doc.OrchestratorManifest == nil {
		doc.OrchestratorManifest = &OrchestratorManifest{}
	}
	if strings.TrimSpace(doc.OrchestratorManifest.AgentID) == "" {
		doc.OrchestratorManifest.AgentID = strings.TrimSpace(doc.AgentID)
	}
	if strings.TrimSpace(doc.OrchestratorManifest.UndeclaredInvocationPolicy) == "" {
		doc.OrchestratorManifest.UndeclaredInvocationPolicy = "deny"
	}
	indexByTarget := make(map[string]int, len(doc.OrchestratorManifest.PermittedInvocations))
	for i, inv := range doc.OrchestratorManifest.PermittedInvocations {
		indexByTarget[strings.TrimSpace(inv.AgentID)] = i
	}
	policyIndexByTarget := make(map[string]int, len(doc.DelegationPolicies))
	for i, p := range doc.DelegationPolicies {
		policyIndexByTarget[strings.TrimSpace(p.TargetAgent)] = i
	}
	for _, delegate := range ag.Delegates {
		if delegate == nil {
			continue
		}
		target := strings.TrimSpace(delegate.TargetAgent)
		if target == "" {
			continue
		}
		requiresApproval := strings.EqualFold(strings.TrimSpace(delegate.Ceiling), "approval")
		if idx, ok := indexByTarget[target]; ok {
			current := doc.OrchestratorManifest.PermittedInvocations[idx]
			if requiresApproval {
				current.RequiresPriorApproval = true
			}
			doc.OrchestratorManifest.PermittedInvocations[idx] = current
		} else {
			doc.OrchestratorManifest.PermittedInvocations = append(doc.OrchestratorManifest.PermittedInvocations, AgentInvocation{
				AgentID:               target,
				RequiresPriorApproval: requiresApproval,
			})
			indexByTarget[target] = len(doc.OrchestratorManifest.PermittedInvocations) - 1
		}

		nextPolicy := DelegationPolicy{
			TargetAgent: target,
			Scope:       strings.TrimSpace(delegate.Scope),
			TTL:         strings.TrimSpace(delegate.TTL),
			Ceiling:     strings.ToLower(strings.TrimSpace(delegate.Ceiling)),
		}
		if idx, ok := policyIndexByTarget[target]; ok {
			current := doc.DelegationPolicies[idx]
			if current.Scope == "" {
				current.Scope = nextPolicy.Scope
			}
			if current.TTL == "" {
				current.TTL = nextPolicy.TTL
			}
			if current.Ceiling == "" {
				current.Ceiling = nextPolicy.Ceiling
			}
			doc.DelegationPolicies[idx] = current
		} else {
			doc.DelegationPolicies = append(doc.DelegationPolicies, nextPolicy)
			policyIndexByTarget[target] = len(doc.DelegationPolicies) - 1
		}
	}
}

func normalizeGuardEffect(raw, field string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", nil
	}
	if v != "deny" && v != "defer" {
		return "", fmt.Errorf("parse FPL: %s=%q is unsupported (supported: deny|defer)", field, strings.TrimSpace(raw))
	}
	return v, nil
}

func delegateToolPattern(scope string) string {
	v := strings.TrimSpace(scope)
	if v == "" {
		return ""
	}
	if idx := strings.Index(v, ":"); idx >= 0 {
		v = strings.TrimSpace(v[:idx])
	}
	return v
}

func parsePositiveIntLimit(raw string) (int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0, fmt.Errorf("value is empty")
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("value must be > 0")
	}
	return n, nil
}

func parseByteSizeLimit(raw string) (int, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return 0, fmt.Errorf("value is empty")
	}
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(v, "tb"):
		multiplier = 1024 * 1024 * 1024 * 1024
		v = strings.TrimSpace(strings.TrimSuffix(v, "tb"))
	case strings.HasSuffix(v, "gb"):
		multiplier = 1024 * 1024 * 1024
		v = strings.TrimSpace(strings.TrimSuffix(v, "gb"))
	case strings.HasSuffix(v, "mb"):
		multiplier = 1024 * 1024
		v = strings.TrimSpace(strings.TrimSuffix(v, "mb"))
	case strings.HasSuffix(v, "kb"):
		multiplier = 1024
		v = strings.TrimSpace(strings.TrimSuffix(v, "kb"))
	case strings.HasSuffix(v, "b"):
		multiplier = 1
		v = strings.TrimSpace(strings.TrimSuffix(v, "b"))
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("value must be > 0")
	}
	maxInt := int64(^uint(0) >> 1)
	if n > maxInt/multiplier {
		return 0, fmt.Errorf("value overflows int")
	}
	return int(n * multiplier), nil
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
	compileEnv := evalEnv(doc, nil)

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
			if _, err := compileExpr(rule.Match.When, compileEnv); err != nil {
				errs = append(errs, fmt.Sprintf("rule %q: invalid when expression: %v", rule.ID, err))
			}
		}
	}

	for i, tr := range doc.PhaseTransitions {
		label := fmt.Sprintf("phase_transition[%d]", i)
		from := strings.TrimSpace(tr.From)
		to := strings.TrimSpace(tr.To)
		if from == "" {
			errs = append(errs, fmt.Sprintf("%s: missing from phase", label))
		}
		if to == "" {
			errs = append(errs, fmt.Sprintf("%s: missing to phase", label))
		}
		effect := normalizePhaseTransitionEffect(tr.Effect)
		if effect == "" {
			errs = append(errs, fmt.Sprintf("%s: invalid effect %q (must be permit_transition|defer)", label, strings.TrimSpace(tr.Effect)))
		}
		if len(doc.Phases) > 0 {
			if from != "" {
				if _, ok := doc.Phases[from]; !ok {
					errs = append(errs, fmt.Sprintf("%s: from phase %q not declared in phases", label, from))
				}
			}
			if to != "" {
				if _, ok := doc.Phases[to]; !ok {
					errs = append(errs, fmt.Sprintf("%s: to phase %q not declared in phases", label, to))
				}
			}
		}
		if strings.TrimSpace(tr.Conditions) != "" {
			if _, err := compileExpr(tr.Conditions, compileEnv); err != nil {
				errs = append(errs, fmt.Sprintf("%s: invalid conditions expression: %v", label, err))
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
