package runtimeenv

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// PythonDeps lists normalized dependency names found in the working directory.
type PythonDeps struct {
	names map[string]struct{}
}

// ScanPythonDeps reads requirements*.txt and pyproject.toml in the project root only.
func ScanPythonDeps(root string) *PythonDeps {
	d := &PythonDeps{names: make(map[string]struct{})}
	if root == "" {
		return d
	}
	mergePyProject(filepath.Join(root, "pyproject.toml"), d.names)
	entries, err := os.ReadDir(root)
	if err != nil {
		return d
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
			mergeReqFile(filepath.Join(root, name), d.names)
		}
	}
	return d
}

func (p *PythonDeps) Has(pkg string) bool {
	if p == nil {
		return false
	}
	_, ok := p.names[strings.ToLower(strings.TrimSpace(pkg))]
	return ok
}

func mergeReqFile(path string, into map[string]struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// strip env markers, extras, versions
		if i := strings.IndexAny(line, " \t[<"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = strings.TrimPrefix(line, `"`)
		line = strings.TrimSuffix(line, `"`)
		if line != "" {
			into[normalizePyPkg(line)] = struct{}{}
		}
	}
}

func mergePyProject(path string, into map[string]struct{}) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// Lightweight scan: dependency tables use quoted or bare package names.
	// We tokenize on non-alphanumeric boundaries and pick known framework tokens.
	s := strings.ToLower(string(b))
	// Split PEP 508 markers so "langgraph>=0.2" yields langgraph.
	seps := " \t\n\r[]()\",'=:#<>!"
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return strings.ContainsRune(seps, r)
	})
	for _, tok := range fields {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if knownPythonFrameworkToken(tok) {
			into[normalizePyPkg(tok)] = struct{}{}
		}
	}
}

func normalizePyPkg(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	// PEP 503 normalization
	s = strings.ReplaceAll(s, ".", "-")
	return s
}

func knownPythonFrameworkToken(tok string) bool {
	switch tok {
	case "deepagents", "langgraph", "langchain", "langchain-core", "crewai",
		"pyautogen", "autogen", "autogen-agentchat", "semantic-kernel",
		"pydantic-ai", "llama-index", "llama-index-core", "smolagents",
		"haystack-ai", "haystack",
		"google-adk", "strands-agents", "strands-agents-builder", "bedrock-agentcore":
		return true
	default:
		return false
	}
}
