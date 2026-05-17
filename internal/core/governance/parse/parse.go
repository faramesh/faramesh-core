package parse

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"gopkg.in/yaml.v3"
)

// ParseStructured reads YAML or JSON governance config into the unified AST.
func ParseStructured(path string, content []byte, syntax ast.Syntax) (*ast.Document, error) {
	switch syntax {
	case ast.SyntaxYAML:
		return parseYAML(path, content)
	case ast.SyntaxJSON:
		return parseJSON(path, content)
	default:
		return nil, fmt.Errorf("unsupported structured syntax %q", syntax)
	}
}

func parseYAML(path string, content []byte) (*ast.Document, error) {
	var raw structuredDocument
	dec := yaml.NewDecoder(bytes.NewReader(content))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return documentFromStructured(ast.SyntaxYAML, path, &raw)
}

func parseJSON(path string, content []byte) (*ast.Document, error) {
	var raw structuredDocument
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	return documentFromStructured(ast.SyntaxJSON, path, &raw)
}
