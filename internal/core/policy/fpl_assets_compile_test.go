package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestFPLAssetsCompileWithEngine(t *testing.T) {
	root := repoRootFromTestFile(t)
	dirs := []string{
		"examples",
		"packs",
		"policies",
		"internal/core/fpl/testdata",
		"internal/core/policy/testdata",
	}

	files := collectFPLFiles(t, root, dirs)
	if len(files) == 0 {
		t.Fatalf("expected FPL files to audit")
	}

	var failures []string
	for _, path := range files {
		doc, version, err := LoadFile(path)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: load error: %v", relPath(root, path), err))
			continue
		}
		if _, err := NewEngine(doc, version); err != nil {
			failures = append(failures, fmt.Sprintf("%s: engine compile error: %v", relPath(root, path), err))
		}
	}

	if len(failures) > 0 {
		t.Fatalf("FPL asset compile audit failed:\n%s", strings.Join(failures, "\n"))
	}
}

func collectFPLFiles(t *testing.T, root string, dirs []string) []string {
	t.Helper()
	var files []string
	for _, dir := range dirs {
		base := filepath.Join(root, dir)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(path), ".fpl") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	sort.Strings(files)
	return files
}

func repoRootFromTestFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	// internal/core/policy -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func relPath(root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return abs
	}
	return rel
}
