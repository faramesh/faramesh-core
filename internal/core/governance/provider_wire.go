package governance

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"github.com/faramesh/faramesh-core/internal/registry"
)

// WireProviderSources sets provider block source paths from downloaded registry binaries.
func WireProviderSources(doc *ast.Document, stackDir string) {
	if doc == nil || len(doc.Imports) == 0 || len(doc.Providers) == 0 {
		return
	}
	stackDir = strings.TrimSpace(stackDir)
	if stackDir == "" {
		return
	}
	for _, imp := range doc.Imports {
		ref := strings.TrimSpace(imp.Ref)
		if ref == "" {
			continue
		}
		parsed, err := registry.ParseImport(ref)
		if err != nil || parsed.Kind != registry.KindProvider {
			continue
		}
		binPath := providerBinaryPath(stackDir, parsed)
		if st, err := os.Stat(binPath); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			continue
		}
		typeHint := providerTypeFromImportName(parsed.Name)
		for _, p := range doc.Providers {
			if strings.TrimSpace(p.Source) != "" {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(p.Type), typeHint) {
				p.Source = binPath
			}
		}
	}
}

func providerBinaryPath(stackDir string, ref registry.Ref) string {
	installDir := filepath.Join(stackDir, ".faramesh", "providers", strings.ReplaceAll(ref.Name, "/", "_")+"@"+ref.Version)
	return filepath.Join(installDir, "provider")
}

func providerTypeFromImportName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}
