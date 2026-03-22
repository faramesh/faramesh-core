package packs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

func TestSeedPacksValidate(t *testing.T) {
	root := "."
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	type packFile struct {
		path  string
		isFPL bool
	}
	var packs []packFile
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		fplPath := filepath.Join(root, e.Name(), "policy.fpl")
		yamlPath := filepath.Join(root, e.Name(), "policy.yaml")
		if st, err := os.Stat(fplPath); err == nil && !st.IsDir() {
			packs = append(packs, packFile{path: fplPath, isFPL: true})
		} else if st, err := os.Stat(yamlPath); err == nil && !st.IsDir() {
			packs = append(packs, packFile{path: yamlPath, isFPL: false})
		}
	}
	if len(packs) < 5 {
		t.Fatalf("expected at least 5 pack policy files, found %d", len(packs))
	}
	for _, pf := range packs {
		pf := pf
		t.Run(filepath.Base(filepath.Dir(pf.path)), func(t *testing.T) {
			if pf.isFPL {
				data, err := os.ReadFile(pf.path)
				if err != nil {
					t.Fatalf("read %s: %v", pf.path, err)
				}
				doc, err := fpl.ParseDocument(string(data))
				if err != nil {
					t.Fatalf("parse FPL %s: %v", pf.path, err)
				}
				_, err = fpl.CompileDocument(doc)
				if err != nil {
					t.Fatalf("compile FPL %s: %v", pf.path, err)
				}
			} else {
				doc, _, err := policy.LoadFile(pf.path)
				if err != nil {
					t.Fatalf("load %s: %v", pf.path, err)
				}
				issues := policy.Validate(doc)
				errs := policy.ValidationErrorsOnly(issues)
				if len(errs) > 0 {
					t.Fatalf("validate %s: %v", pf.path, errs)
				}
				if _, err := policy.NewEngine(doc, "test"); err != nil {
					t.Fatalf("compile %s: %v", pf.path, err)
				}
			}
		})
	}
}
