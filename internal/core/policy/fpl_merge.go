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
		p, err := fpl.ParseProgram(s)
		if err != nil {
			return nil, fmt.Errorf("fpl_inline: %w", err)
		}
		topoStmts = append(topoStmts, p.Topo...)
		c, err := fpl.CompileRules(p.Rules)
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
		p, err := fpl.ParseProgram(string(b))
		if err != nil {
			return nil, fmt.Errorf("compile fpl_files %q: %w", rel, err)
		}
		topoStmts = append(topoStmts, p.Topo...)
		c, err := fpl.CompileRules(p.Rules)
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
	return Rule{
		ID:         fmt.Sprintf("fpl-%d", seq),
		Match:      Match{Tool: cr.Tool, When: when},
		Effect:     effect,
		Reason:     cr.Reason,
		ReasonCode: cr.ReasonCode,
	}
}
