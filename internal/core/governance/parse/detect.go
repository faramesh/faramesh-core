package parse

import (
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

// DetectSyntax determines the surface syntax for governance config bytes.
// path is used for .yaml/.json extensions; content sniffing applies to governance.fms.
func DetectSyntax(path string, content []byte) ast.Syntax {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return ast.SyntaxYAML
	case ".json":
		return ast.SyntaxJSON
	}
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "governance.fms.yaml", "governance.fms.yml":
		return ast.SyntaxYAML
	case "governance.fms.json":
		return ast.SyntaxJSON
	}
	return sniffSyntax(content)
}

func sniffSyntax(content []byte) ast.Syntax {
	i := 0
	for i < len(content) {
		switch content[i] {
		case ' ', '\t', '\r':
			i++
			continue
		case '\n':
			i++
			continue
		case '#':
			for i < len(content) && content[i] != '\n' {
				i++
			}
			continue
		default:
			if content[i] == '{' {
				return ast.SyntaxJSON
			}
			lineStart := i
			for i < len(content) && content[i] != '\n' {
				i++
			}
			line := strings.TrimSpace(string(content[lineStart:i]))
			if line == "---" {
				return ast.SyntaxYAML
			}
			return ast.SyntaxFPL
		}
	}
	return ast.SyntaxFPL
}
