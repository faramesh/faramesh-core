package governance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"github.com/faramesh/faramesh-core/internal/hub"
	"github.com/faramesh/faramesh-core/internal/registry"
)

// ResolveImports fetches registry packs, verifies signatures, and merges into doc.
func ResolveImports(doc *ast.Document, offline bool) error {
	if doc == nil || len(doc.Imports) == 0 {
		return nil
	}
	if offline {
		return nil
	}
	stackDir := filepath.Dir(doc.SourcePath)
	if stackDir == "." {
		stackDir, _ = os.Getwd()
	}
	cacheDir := filepath.Join(stackDir, ".faramesh", "import-cache")
	_ = os.MkdirAll(cacheDir, 0o755)

	baseURL := registryBaseURL("")
	client, err := hub.NewClient(baseURL)
	if err != nil {
		return err
	}
	reg := registry.NewClient(client)

	for _, imp := range doc.Imports {
		ref := strings.TrimSpace(imp.Ref)
		if ref == "" {
			return fmt.Errorf("import: empty ref")
		}
		parsed, err := registry.ParseImport(ref)
		if err != nil {
			return err
		}
		if parsed.Kind == registry.KindProvider {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		pv, err := reg.FetchFPLPack(ctx, parsed)
		cancel()
		if err != nil {
			loc := importLocation(doc, imp)
			if strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_URL")) == "" {
				return fmt.Errorf("%s — import %q\n  Registry URL not configured and pack not in local bundle.\n  Set FARAMESH_REGISTRY_URL or run faramesh bundle for offline use.", loc, ref)
			}
			return fmt.Errorf("import %q: fetch failed: %w", ref, err)
		}
		policyBytes := []byte(pv.PolicyFPL)
		if len(policyBytes) == 0 {
			policyBytes = []byte(pv.PolicyYAML)
		}
		if len(policyBytes) == 0 {
			return fmt.Errorf("import %q: pack has no policy_fpl or policy_yaml", ref)
		}
		if want := strings.TrimSpace(pv.SHA256Hex); want != "" {
			sum := sha256.Sum256(policyBytes)
			if hex.EncodeToString(sum[:]) != strings.ToLower(want) {
				return fmt.Errorf("import %q: sha256 mismatch", ref)
			}
		}
		if pv.Signature != nil {
			if err := hub.VerifyPolicySignature(policyBytes, pv.Signature); err != nil {
				return fmt.Errorf("import %q: signature: %w", ref, err)
			}
		}
		cachePath := filepath.Join(cacheDir, string(parsed.Kind), strings.ReplaceAll(parsed.Name, "/", "_")+"@"+parsed.Version+".fpl")
		_ = os.MkdirAll(filepath.Dir(cachePath), 0o755)
		if err := os.WriteFile(cachePath, policyBytes, 0o644); err != nil {
			return err
		}
		imported, err := parseImportedPolicy(policyBytes, cachePath)
		if err != nil {
			return fmt.Errorf("import %q: parse: %w", ref, err)
		}
		mergeImportedDocument(doc, imported)
	}
	return nil
}

func importLocation(doc *ast.Document, imp ast.Import) string {
	loc := doc.SourcePath
	if loc == "" {
		loc = "governance.fms"
	}
	line := imp.Line
	if line <= 0 {
		line = 1
	}
	return fmt.Sprintf("%s:%d", loc, line)
}

func registryBaseURL(host string) string {
	if v := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_URL")); v != "" {
		return v
	}
	if strings.TrimSpace(host) == "" {
		host = registry.DefaultHost
	}
	return "https://" + host
}

func parseImportedPolicy(b []byte, path string) (*ast.Document, error) {
	doc, err := ParseSource(path, b)
	if err != nil {
		return nil, err
	}
	doc.SourcePath = path
	return doc, nil
}

func mergeImportedDocument(dst, src *ast.Document) {
	if dst == nil || src == nil {
		return
	}
	if dst.Agents == nil {
		dst.Agents = make(map[string]*ast.Agent)
	}
	for id, ag := range src.Agents {
		if _, exists := dst.Agents[id]; exists {
			continue
		}
		dst.Agents[id] = ag
	}
	for _, r := range src.FlatRules {
		dst.FlatRules = append(dst.FlatRules, r)
	}
	if dst.Runtime == nil && src.Runtime != nil {
		dst.Runtime = src.Runtime
	}
	for name, p := range src.Providers {
		if _, exists := dst.Providers[name]; !exists {
			if dst.Providers == nil {
				dst.Providers = make(map[string]*ast.Provider)
			}
			dst.Providers[name] = p
		}
	}
}
