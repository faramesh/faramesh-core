package packs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

type packFile struct {
	name  string
	path  string
	isFPL bool
}

func TestSeedPacksValidate(t *testing.T) {
	root := "."
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	var packs []packFile
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(root, e.Name())
		yamlPath := filepath.Join(dir, "policy.yaml")
		fplPath := filepath.Join(dir, "policy.fpl")
		base := e.Name()
		if _, err := os.Stat(yamlPath); err == nil {
			packs = append(packs, packFile{name: base + "/policy.yaml", path: yamlPath, isFPL: false})
		}
		if _, err := os.Stat(fplPath); err == nil {
			packs = append(packs, packFile{name: base + "/policy.fpl", path: fplPath, isFPL: true})
		}
	}
	if len(packs) < 10 {
		t.Fatalf("expected at least 10 pack policy file checks (yaml and/or fpl), found %d", len(packs))
	}
	for _, pf := range packs {
		pf := pf
		t.Run(pf.name, func(t *testing.T) {
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
				return
			}
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
		})
	}
}
