package policy

import (
	"crypto/sha256"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

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
// without evaluating them. Returns a list of human-readable errors.
func Validate(doc *Doc) []string {
	var errs []string
	for i, rule := range doc.Rules {
		if rule.ID == "" {
			errs = append(errs, fmt.Sprintf("rule[%d]: missing id", i))
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
	return errs
}
