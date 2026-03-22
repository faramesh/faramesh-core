package packs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

func TestSeedPacksValidate(t *testing.T) {
	root := "."
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(root, e.Name(), "policy.yaml")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			dirs = append(dirs, p)
		}
	}
	if len(dirs) < 5 {
		t.Fatalf("expected at least 5 pack policy.yaml files, found %d: %v", len(dirs), dirs)
	}
	for _, path := range dirs {
		path := path
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			doc, _, err := policy.LoadFile(path)
			if err != nil {
				t.Fatalf("load %s: %v", path, err)
			}
			issues := policy.Validate(doc)
			errs := policy.ValidationErrorsOnly(issues)
			if len(errs) > 0 {
				t.Fatalf("validate %s: %v", path, errs)
			}
			if _, err := policy.NewEngine(doc, "test"); err != nil {
				t.Fatalf("compile %s: %v", path, err)
			}
		})
	}
}
