package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

// mergeFPLIntoDoc parses FPL from fpl_inline and fpl_files, appends compiled rules after
// existing YAML rules (first-match-wins: YAML rules take precedence over FPL on overlap),
// then clears FPL fields. Returns bytes to fold into the policy version hash.
func mergeFPLIntoDoc(doc *Doc, policyDir string) ([]byte, error) {
	if doc == nil {
		return nil, nil
	}
	if len(doc.FPLFiles) > 0 && policyDir == "" {
		return nil, fmt.Errorf("fpl_files requires loading from a file path (use LoadFile)")
	}

	var digest []byte
	var compiled []*fpl.CompiledRule
	var topoStmts []fpl.TopoStatement

	if s := strings.TrimSpace(doc.FPLInline); s != "" {
		parsed, err := fpl.ParseDocument(s)
		if err != nil {
			return nil, fmt.Errorf("fpl_inline: %w", err)
		}
		if err := validateEmbeddedFPLDocument(parsed, "fpl_inline"); err != nil {
			return nil, err
		}
		topoStmts = append(topoStmts, parsed.Topo...)
		c, err := fpl.CompileRules(parsed.FlatRules)
		if err != nil {
			return nil, fmt.Errorf("fpl_inline: %w", err)
		}
		compiled = append(compiled, c...)
		digest = append(digest, []byte(s)...)
	}

	baseAbs, err := filepath.Abs(policyDir)
	if err != nil {
		return nil, err
	}
	for _, rel := range doc.FPLFiles {
		clean := filepath.Clean(rel)
		if clean == "." || strings.HasPrefix(clean, "..") {
			return nil, fmt.Errorf("fpl_files: invalid path %q", rel)
		}
		full := filepath.Join(policyDir, clean)
		fullAbs, err := filepath.Abs(full)
		if err != nil {
			return nil, err
		}
		if fullAbs != baseAbs && !strings.HasPrefix(fullAbs, baseAbs+string(os.PathSeparator)) {
			return nil, fmt.Errorf("fpl_files: path %q escapes policy directory", rel)
		}
		b, err := os.ReadFile(fullAbs)
		if err != nil {
			return nil, fmt.Errorf("read fpl_files %q: %w", rel, err)
		}
		parsed, err := fpl.ParseDocument(string(b))
		if err != nil {
			return nil, fmt.Errorf("compile fpl_files %q: %w", rel, err)
		}
		if err := validateEmbeddedFPLDocument(parsed, fmt.Sprintf("fpl_files %q", rel)); err != nil {
			return nil, err
		}
		topoStmts = append(topoStmts, parsed.Topo...)
		c, err := fpl.CompileRules(parsed.FlatRules)
		if err != nil {
			return nil, fmt.Errorf("compile fpl_files %q: %w", rel, err)
		}
		compiled = append(compiled, c...)
		digest = append(digest, b...)
	}

	if err := mergeOrchestratorManifestFromFPL(doc, topoStmts); err != nil {
		return nil, err
	}

	doc.FPLInline = ""
	doc.FPLFiles = nil

	base := len(doc.Rules)
	for i, cr := range compiled {
		doc.Rules = append(doc.Rules, compiledRuleToRule(cr, base+i))
	}
	return digest, nil
}

func compiledRuleToRule(cr *fpl.CompiledRule, seq int) Rule {
	effect := string(cr.Effect)
	if cr.StrictDeny {
		effect = "deny"
	}
	when := strings.TrimSpace(cr.When)
	if when == "" {
		when = "true"
	}
	notify := ""
	if cr.Notify != nil {
		notify = strings.TrimSpace(cr.Notify.Target)
	}
	return Rule{
		ID:         fmt.Sprintf("fpl-%d", seq),
		Match:      Match{Tool: cr.Tool, When: when},
		Effect:     effect,
		Notify:     notify,
		Reason:     cr.Reason,
		ReasonCode: cr.ReasonCode,
	}
}

func validateEmbeddedFPLDocument(parsed *fpl.Document, source string) error {
	if parsed == nil {
		return fmt.Errorf("%s: empty document", source)
	}
	if len(parsed.Agents) > 0 || len(parsed.Systems) > 0 {
		return fmt.Errorf("%s: embedded FPL only supports flat rule/manifest snippets (agent/system blocks are not allowed)", source)
	}
	return nil
}
