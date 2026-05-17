// Package initwriter implements faramesh init scaffolding per FARAMESH.md §10.
package initwriter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const governanceFile = "governance.fms"

// Options configures init output.
type Options struct {
	Dir              string
	Offline          bool
	NonInteractive   bool
	FormatYAML       bool
	FormatJSON       bool
	SelectedFramework string // when user picks interactively
}

// Result describes what was written.
type Result struct {
	Framework     string
	Tools         []DiscoveredTool
	OutputPath    string
	AlreadyExists bool
}

// DiscoveredTool is one tool registration found in the project tree.
type DiscoveredTool struct {
	Name string
	Path string
	Line int
	Kind string
}

// Run performs init in stackDir and returns the result for terminal output.
func Run(opts Options) (*Result, error) {
	stackDir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, err
	}
	outName := governanceFile
	if opts.FormatYAML {
		outName = "governance.fms.yaml"
	} else if opts.FormatJSON {
		outName = "governance.fms.json"
	}
	outPath := filepath.Join(stackDir, outName)
	if _, err := os.Stat(outPath); err == nil {
		return &Result{AlreadyExists: true, OutputPath: outPath}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	framework := strings.TrimSpace(opts.SelectedFramework)
	if framework == "" {
		framework, _ = DetectFramework(stackDir)
	}
	if framework == "" && opts.NonInteractive {
		framework = "unknown"
	}
	tools := DiscoverTools(stackDir, framework)
	if framework == "" {
		return nil, fmt.Errorf("framework not detected; re-run with an interactive terminal or pass --non-interactive after selecting a framework")
	}

	content := RenderFPL(stackDir, framework, tools, opts.Offline, opts.NonInteractive && framework == "unknown")
	if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
		return nil, err
	}
	return &Result{
		Framework:  framework,
		Tools:      tools,
		OutputPath: outPath,
	}, nil
}

// DetectFramework scans the stack directory per §10.3 precedence.
func DetectFramework(stackDir string) (string, []string) {
	var matches []string
	add := func(id string) {
		for _, m := range matches {
			if m == id {
				return
			}
		}
		matches = append(matches, id)
	}

	if id := detectPythonFramework(stackDir); id != "" {
		add(id)
	}
	if id := detectNodeFramework(stackDir); id != "" {
		add(id)
	}
	if detectDeepAgents(stackDir) {
		add("deep-agents")
	}

	if len(matches) == 1 {
		return matches[0], matches
	}
	if len(matches) > 1 {
		return "", matches
	}
	return "", nil
}

func detectPythonFramework(stackDir string) string {
	deps := map[string]struct{}{}
	for _, name := range []string{"pyproject.toml", "requirements.txt"} {
		p := filepath.Join(stackDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(strings.ToLower(line))
			line = strings.TrimPrefix(line, "dependencies = [")
			line = strings.Trim(line, `",[] `)
			if line != "" {
				deps[line] = struct{}{}
			}
		}
	}
	matches, _ := filepath.Glob(filepath.Join(stackDir, "requirements*.txt"))
	for _, rp := range matches {
		b, err := os.ReadFile(rp)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			pkg := strings.TrimSpace(strings.ToLower(strings.Split(line, "==")[0]))
			pkg = strings.Split(pkg, ">=")[0]
			pkg = strings.Split(pkg, "[")[0]
			if pkg != "" {
				deps[pkg] = struct{}{}
			}
		}
	}
	has := func(pkgs ...string) bool {
		for _, p := range pkgs {
			if _, ok := deps[p]; ok {
				return true
			}
		}
		return false
	}
	switch {
	case has("langgraph"):
		return "langgraph"
	case has("langchain"):
		return "langgraph"
	case has("crewai"):
		return "crewai"
	case has("autogen", "ag2"):
		return "ag2"
	case has("google-adk", "google.adk"):
		return "google-adk"
	case has("openai-agents", "agents"):
		return "openai-agents"
	case has("anthropic"):
		if treeHasAgentPatterns(stackDir) {
			return "anthropic-sdk"
		}
	case has("strands-agents"):
		return "strands"
	case has("boto3"):
		if hasBedrockPatterns(stackDir) {
			return "bedrock"
		}
	case has("fastmcp", "mcp"):
		return "mcp"
	}
	return ""
}

func detectNodeFramework(stackDir string) string {
	b, err := os.ReadFile(filepath.Join(stackDir, "package.json"))
	if err != nil {
		return ""
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return ""
	}
	all := map[string]struct{}{}
	for k := range pkg.Dependencies {
		all[strings.ToLower(k)] = struct{}{}
	}
	for k := range pkg.DevDependencies {
		all[strings.ToLower(k)] = struct{}{}
	}
	has := func(name string) bool {
		_, ok := all[strings.ToLower(name)]
		return ok
	}
	switch {
	case has("@langchain/langgraph"), has("langgraph"), has("langchain"):
		return "langgraph"
	case has("crewai"):
		return "crewai"
	case has("@anthropic-ai/sdk"), has("anthropic"):
		return "anthropic-sdk"
	case has("@openai/agents"), has("openai-agents"):
		return "openai-agents"
	case has("@modelcontextprotocol/sdk"), has("fastmcp"):
		return "mcp"
	}
	return ""
}

func detectDeepAgents(stackDir string) bool {
	for _, name := range []string{"deepagents.toml", "agents.toml", "AGENTS.md"} {
		if _, err := os.Stat(filepath.Join(stackDir, name)); err == nil {
			return true
		}
	}
	return false
}

func treeHasAgentPatterns(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				base := filepath.Base(path)
				if base == ".git" || base == "node_modules" || base == ".venv" || base == "vendor" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".py") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		s := string(b)
		if strings.Contains(s, "@tool") || strings.Contains(s, "Tool(") || strings.Contains(s, "tools=[") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func hasBedrockPatterns(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		s := strings.ToLower(string(b))
		if strings.Contains(s, "actiongroup") || strings.Contains(s, "action_group") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

var (
	rePyTool       = regexp.MustCompile(`@tool\b|Tool\s*\(|StructuredTool\s*\(|\.tool\s*\(`)
	reCrewTool     = regexp.MustCompile(`@tool\b|Tool\s*\(|BaseTool`)
	reAg2          = regexp.MustCompile(`register_function\s*\(|@register_for_execution|@register_for_llm`)
	reGoogleTool   = regexp.MustCompile(`@tool\b|FunctionTool\s*\(|tools\s*=\s*\[`)
	reOpenAITool   = regexp.MustCompile(`@function_tool|FunctionTool\s*\(|tools\s*=\s*\[`)
	reMCP          = regexp.MustCompile(`server\.tool\s*\(|@mcp\.tool\s*\(|add_tool\s*\(`)
	reToolName     = regexp.MustCompile(`(?:def|async def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	reToolAssign   = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:Tool|StructuredTool|FunctionTool)\s*\(`)
)

// DiscoverTools finds tool registrations for the given framework.
func DiscoverTools(stackDir, framework string) []DiscoveredTool {
	var out []DiscoveredTool
	seen := map[string]struct{}{}
	add := func(name, path string, line int, kind string) {
		name = normalizeToolID(name)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		rel, _ := filepath.Rel(stackDir, path)
		if rel == "" {
			rel = path
		}
		out = append(out, DiscoveredTool{Name: name, Path: rel, Line: line, Kind: kind})
	}

	switch framework {
	case "deep-agents":
		_ = filepath.WalkDir(filepath.Join(stackDir, "skills"), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Base(path), "SKILL.md") {
				name := strings.TrimSuffix(filepath.Base(filepath.Dir(path)), "")
				if name == "skills" {
					name = strings.TrimSuffix(filepath.Base(path), ".md")
				}
				add(filepath.Base(filepath.Dir(path)), path, 1, "skill")
			}
			return nil
		})
		return out
	case "bedrock":
		scanFiles(stackDir, []string{".json", ".yaml", ".yml"}, func(path string, line int, lineText string) {
			if strings.Contains(strings.ToLower(lineText), "name") && strings.Contains(strings.ToLower(lineText), "action") {
				// best-effort: extract quoted name
				if m := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`).FindStringSubmatch(lineText); len(m) == 2 {
					add(m[1], path, line, "action_group")
				}
			}
		})
		return out
	}

	var re *regexp.Regexp
	kind := "@tool"
	switch framework {
	case "langgraph", "langchain":
		re = rePyTool
	case "crewai":
		re = reCrewTool
	case "ag2":
		re = reAg2
		kind = "register_function"
	case "google-adk":
		re = reGoogleTool
	case "openai-agents":
		re = reOpenAITool
	case "mcp":
		re = reMCP
		kind = "mcp.tool"
	default:
		re = rePyTool
	}

	scanFiles(stackDir, []string{".py", ".ts", ".js", ".tsx", ".jsx"}, func(path string, line int, lineText string) {
		if !re.MatchString(lineText) {
			return
		}
		name := ""
		if m := reToolAssign.FindStringSubmatch(lineText); len(m) == 2 {
			name = m[1]
		} else if strings.Contains(lineText, "def ") {
			if m := reToolName.FindStringSubmatch(lineText); len(m) == 2 {
				name = m[1]
			}
		}
		if name == "" {
			name = fmt.Sprintf("tool_%d", line)
		}
		add(name, path, line, kind)
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func scanFiles(root string, exts []string, fn func(path string, line int, lineText string)) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				base := filepath.Base(path)
				if base == ".git" || base == "node_modules" || base == ".venv" || base == "vendor" || base == "dist" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		okExt := false
		for _, e := range exts {
			if ext == e {
				okExt = true
				break
			}
		}
		if !okExt {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		lineNum := 0
		for sc.Scan() {
			lineNum++
			fn(path, lineNum, sc.Text())
		}
		return nil
	})
}

func normalizeToolID(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

// RenderFPL builds governance.fms bytes per §10.5–10.7.
func RenderFPL(stackDir, framework string, tools []DiscoveredTool, offline, unknownFramework bool) string {
	stackName := filepath.Base(stackDir)
	agentName := stackName + "-agent"
	agentName = strings.ReplaceAll(agentName, " ", "-")
	generatedAt := time.Now().UTC().Format(time.RFC3339)

	importLine := fmt.Sprintf(`import "github.com/faramesh/faramesh-registry/frameworks/%s@1.0.0"`, framework)
	if offline {
		importLine = ""
	}
	if unknownFramework {
		importLine = `# TODO: import "github.com/faramesh/faramesh-registry/frameworks/<framework>@1.0.0"`
		framework = "unknown"
	}

	var b strings.Builder
	b.WriteString("# governance.fms\n")
	b.WriteString("# Generated by faramesh init\n")
	fmt.Fprintf(&b, "# Stack: %s\n", stackName)
	fmt.Fprintf(&b, "# Framework: %s\n", framework)
	fmt.Fprintf(&b, "# Generated: %s\n", generatedAt)
	b.WriteString("#\n")
	b.WriteString("# faramesh dev    — run governance locally, no external infrastructure\n")
	b.WriteString("# faramesh apply  — start enforcement\n")
	b.WriteString("# Docs: https://docs.faramesh.dev\n\n")
	if importLine != "" {
		b.WriteString(importLine)
		b.WriteString("\n")
	}
	b.WriteString("\nruntime {\n")
	b.WriteString("  mode    = \"enforce\"\n")
	b.WriteString("  wal_dir = \"./faramesh-wal\"\n")
	b.WriteString("  backend = \"sqlite\"\n")
	b.WriteString("}\n\n")
	b.WriteString("# No provider declared — faramesh dev provides built-in stubs.\n")
	b.WriteString("# For production, add a provider block. See: https://docs.faramesh.dev/providers\n\n")
	fmt.Fprintf(&b, "agent \"%s\" {\n", agentName)
	if len(tools) > 0 {
		b.WriteString("  # Tools discovered in this project:\n")
		for _, t := range tools {
			fmt.Fprintf(&b, "  #   %s — %s:%d (%s)\n", t.Name, t.Path, t.Line, t.Kind)
		}
		b.WriteString("\n  rules {\n")
		b.WriteString("    # All discovered tools defer by default. Review: faramesh approvals list\n")
		b.WriteString("    # Change to permit after review: permit <tool-name>\n")
		for _, t := range tools {
			fmt.Fprintf(&b, "    defer %s\n", t.Name)
		}
		b.WriteString("  }\n\n")
	} else {
		b.WriteString("  # No tools were discovered in this project.\n")
		b.WriteString("  # Add rules when you register tools. See: https://docs.faramesh.dev/fpl\n\n")
		b.WriteString("  rules {\n")
		b.WriteString("    # Example: defer my_tool\n")
		b.WriteString("  }\n\n")
	}
	b.WriteString("  budget daily {\n")
	b.WriteString("    max $10.00\n")
	b.WriteString("    warn_at 0.8\n")
	b.WriteString("    on_exceed deny\n")
	b.WriteString("  }\n\n")
	b.WriteString("  egress {\n")
	b.WriteString("    # No external egress permitted by default.\n")
	b.WriteString("    # allow = [\"api.example.com\"]\n")
	b.WriteString("  }\n")
	if framework == "mcp" {
		b.WriteString("\n  enforcement {\n")
		b.WriteString("    mcp_proxy_port = 8081\n")
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}
