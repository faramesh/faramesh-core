package governance

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"github.com/faramesh/faramesh-core/internal/registry"
)

// RecordProviderImports records provider import pins for apply-time binary download (not check/plan).
func RecordProviderImports(doc *ast.Document) error {
	if doc == nil || len(doc.Imports) == 0 {
		return nil
	}
	stackDir := filepath.Dir(doc.SourcePath)
	if stackDir == "." {
		stackDir, _ = os.Getwd()
	}
	for _, imp := range doc.Imports {
		ref := strings.TrimSpace(imp.Ref)
		if ref == "" {
			continue
		}
		parsed, err := registry.ParseImport(ref)
		if err != nil {
			return err
		}
		if parsed.Kind != registry.KindProvider {
			continue
		}
		marker := filepath.Join(stackDir, ".faramesh", "import-cache", "providers", parsed.Name+"@"+parsed.Version+".resolved")
		_ = os.MkdirAll(filepath.Dir(marker), 0o755)
		_ = os.WriteFile(marker, []byte(parsed.ImportLine()+"\n"), 0o644)
	}
	return nil
}
