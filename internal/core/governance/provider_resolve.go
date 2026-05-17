package governance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"github.com/faramesh/faramesh-core/internal/registry"
)

// ResolveProviderImports downloads signed provider binaries referenced by import lines.
func ResolveProviderImports(doc *ast.Document, stackDir string, offline bool) error {
	if doc == nil || len(doc.Imports) == 0 {
		return nil
	}
	if offline {
		return nil
	}
	stackDir = strings.TrimSpace(stackDir)
	if stackDir == "" || stackDir == "." {
		var err error
		stackDir, err = os.Getwd()
		if err != nil {
			return err
		}
	}

	reg, err := registry.NewResolver()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

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
		installDir := filepath.Join(stackDir, ".faramesh", "providers", strings.ReplaceAll(parsed.Name, "/", "_")+"@"+parsed.Version)
		binPath := filepath.Join(installDir, "provider")
		if info, err := os.Stat(binPath); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			continue
		}
		if _, err := reg.InstallProviderBinary(ctx, parsed, stackDir); err != nil {
			return fmt.Errorf("provider import %q: %w", ref, err)
		}
		marker := filepath.Join(stackDir, ".faramesh", "import-cache", "providers", parsed.Name+"@"+parsed.Version+".resolved")
		_ = os.MkdirAll(filepath.Dir(marker), 0o755)
		_ = os.WriteFile(marker, []byte(parsed.ImportLine()+"\n"), 0o644)
	}
	return nil
}
