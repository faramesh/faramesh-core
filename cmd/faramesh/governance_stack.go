package main

import (
	"fmt"
	"os"

	"github.com/faramesh/faramesh-core/internal/core/governance"
)

var stackDirFlag string

func resolveStackDir() (string, error) {
	return governance.ResolveStackDir(stackDirFlag)
}

func loadGovernanceStack() (*governance.Compiled, []governance.Diagnostic, error) {
	stackDir, err := resolveStackDir()
	if err != nil {
		return nil, nil, err
	}
	path, content, err := governance.FindSource(stackDir)
	if err != nil {
		return nil, nil, err
	}
	doc, _, err := governance.LoadDocument(stackDir)
	if err != nil {
		return nil, nil, err
	}
	compiled, diags, err := governance.Compile(doc, stackDir, content, governance.CompileOptions{CheckEnv: true})
	if err != nil {
		return nil, diags, err
	}
	_ = path
	return compiled, diags, nil
}

func printCheckOK() {
	fmt.Fprintln(os.Stdout, "✓ governance.fms valid")
}

func printCompiledOK() {
	fmt.Fprintln(os.Stdout, "✓ governance.fms compiled")
}
