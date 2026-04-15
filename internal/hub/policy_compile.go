package hub

import (
	"fmt"
	"path/filepath"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"gopkg.in/yaml.v3"
)

const compiledPolicyFile = "policy.compiled.yaml"

// MaterializePolicyCompiledYAML loads policy.yaml from packDir (same semantics as the
// policy engine), marshals the resulting Doc to YAML, and returns bytes
// suitable for policy.compiled.yaml. The on-disk policy.fpl sidecar is not merged
// unless policy.yaml references it via fpl_files (embedded flat FPL only).
func MaterializePolicyCompiledYAML(packDir string) ([]byte, error) {
	policyPath := filepath.Join(packDir, "policy.yaml")
	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy for compile artifact: %w", err)
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal compiled policy yaml: %w", err)
	}
	return out, nil
}
