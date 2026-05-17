package governance

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	FileFPL          = "governance.fms"
	FileYAML         = "governance.fms.yaml"
	FileYML          = "governance.fms.yml"
	FileJSON         = "governance.fms.json"
	CompiledJSON     = "governance.compiled.json"
	PolicyFPL        = "governance.policy.fpl"
	DirFarameshState = ".faramesh"
)

// ResolveStackDir returns an absolute stack directory path.
func ResolveStackDir(dir string) (string, error) {
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return abs, nil
}

// FindSource locates the governance source file in stackDir.
func FindSource(stackDir string) (path string, content []byte, err error) {
	candidates := []string{FileFPL, FileYAML, FileYML, FileJSON}
	for _, name := range candidates {
		p := filepath.Join(stackDir, name)
		b, readErr := os.ReadFile(p)
		if readErr == nil {
			return p, b, nil
		}
		if !os.IsNotExist(readErr) {
			return "", nil, readErr
		}
	}
	return "", nil, fmt.Errorf("no governance config found in %s (expected %s)", stackDir, FileFPL)
}

// CompiledPath returns the path to the compiled artifact in stackDir.
func CompiledPath(stackDir string) string {
	return filepath.Join(stackDir, CompiledJSON)
}

// PolicyPath returns the materialized policy FPL path in stackDir.
func PolicyPath(stackDir string) string {
	return filepath.Join(stackDir, PolicyFPL)
}
