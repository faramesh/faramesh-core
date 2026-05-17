package initwriter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderFPLWithTools(t *testing.T) {
	dir := t.TempDir()
	tools := []DiscoveredTool{
		{Name: "search_docs", Path: "agent.py", Line: 12, Kind: "@tool"},
	}
	out := RenderFPL(dir, "langgraph", tools, false, false)
	if !strings.Contains(out, `import "registry.faramesh.dev/frameworks/langgraph@1.0.0"`) {
		t.Fatalf("missing import: %s", out)
	}
	if !strings.Contains(out, "defer search_docs") {
		t.Fatalf("missing defer: %s", out)
	}
}

func TestRunRefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, governanceFile)
	if err := os.WriteFile(path, []byte("# existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{Dir: dir, SelectedFramework: "mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.AlreadyExists {
		t.Fatal("expected already exists")
	}
}
