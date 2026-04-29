package policy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestRepoFPLAssetsCompileViaEngine(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	assetRoots := []string{
		filepath.Join(repoRoot, "examples"),
		filepath.Join(repoRoot, "policies"),
	}

	var fplFiles []string
	for _, root := range assetRoots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(path), ".fpl") {
				fplFiles = append(fplFiles, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(fplFiles) == 0 {
		t.Fatal("expected at least one .fpl policy asset")
	}
	sort.Strings(fplFiles)

	for _, path := range fplFiles {
		doc, version, err := LoadFile(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		issues := ValidationErrorsOnly(Validate(doc))
		if len(issues) > 0 {
			t.Fatalf("validate %s: %v", path, issues)
		}
		if _, err := NewEngine(doc, version); err != nil {
			t.Fatalf("compile %s: %v", path, err)
		}
	}
}
