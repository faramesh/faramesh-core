package governance

import (
	"fmt"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	govparse "github.com/faramesh/faramesh-core/internal/core/governance/parse"
)

// LoadDocument reads and parses the governance source from stackDir.
func LoadDocument(stackDir string) (*ast.Document, string, error) {
	path, content, err := FindSource(stackDir)
	if err != nil {
		return nil, "", err
	}
	doc, err := ParseSource(path, content)
	if err != nil {
		return nil, path, fmt.Errorf("parse governance: %w", err)
	}
	doc.SourcePath = path
	return doc, path, nil
}

// ParseSource parses governance bytes from path (syntax from path + content sniffing).
func ParseSource(path string, content []byte) (*ast.Document, error) {
	syntax := govparse.DetectSyntax(path, content)
	switch syntax {
	case ast.SyntaxFPL:
		fplDoc, err := fpl.ParseDocument(string(content))
		if err != nil {
			return nil, fmt.Errorf("parse fpl: %w", err)
		}
		return FromFPL(fplDoc, path), nil
	default:
		return govparse.ParseStructured(path, content, syntax)
	}
}
