package runtimeenv

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// DiscoveryReport is the static project inventory used for observe-first onboarding.
type DiscoveryReport struct {
	Root                 string               `json:"root"`
	Environment          *DetectedEnvironment `json:"environment,omitempty"`
	Frameworks           []string             `json:"frameworks,omitempty"`
	MCPConfigFiles       []string             `json:"mcp_config_files,omitempty"`
	ManifestFiles        []string             `json:"manifest_files,omitempty"`
	NotebookFiles        []string             `json:"notebook_files,omitempty"`
	NetworkReferences    []string             `json:"network_references,omitempty"`
	ShellReferences      []string             `json:"shell_references,omitempty"`
	CredentialReferences []string             `json:"credential_references,omitempty"`
	CandidateTools       []DiscoveredTool     `json:"candidate_tools,omitempty"`
	Stats                DiscoveryStats       `json:"stats"`
}

// DiscoveredTool is a best-effort tool/action surface inferred from static code.
type DiscoveredTool struct {
	ID      string `json:"id"`
	Surface string `json:"surface"`
	Source  string `json:"source"`
	File    string `json:"file"`
}

// DiscoveryStats summarizes scanned file counts.
type DiscoveryStats struct {
	FilesScanned int `json:"files_scanned"`
	PythonFiles  int `json:"python_files"`
	NodeFiles    int `json:"node_files"`
	JSONFiles    int `json:"json_files"`
}

var (
	toolLiteralRe       = regexp.MustCompile(`(?m)(?:name|tool_id|toolId|method)\s*[:=]\s*["']([A-Za-z0-9_.-]+/[A-Za-z0-9_.:-]+)["']`)
	urlLiteralRe        = regexp.MustCompile(`https?://[^\s"'<>]+`)
	ignoreDiscoverDirs  = map[string]struct{}{"node_modules": {}, ".git": {}, ".venv": {}, "venv": {}, "dist": {}, "build": {}, "vendor": {}, "__pycache__": {}}
	nodeFrameworkTokens = map[string]string{
		"@langchain/core":           "langchain-js",
		"langchain":                 "langchain-js",
		"@langchain/langgraph":      "langgraph-js",
		"langgraph":                 "langgraph-js",
		"@modelcontextprotocol/sdk": "mcp-node-sdk",
		"openai-agents":             "openai-agents-sdk",
		"openai-agents-js":          "openai-agents-sdk",
	}
)

// DiscoverProject walks a repo and builds a static inventory of likely action surfaces.
func DiscoverProject(root string) *DiscoveryReport {
	if strings.TrimSpace(root) == "" {
		root, _ = os.Getwd()
	}
	report := &DiscoveryReport{
		Root:        root,
		Environment: DetectEnvironment(root),
	}

	frameworks := map[string]struct{}{}
	if report.Environment != nil && strings.TrimSpace(report.Environment.Framework) != "" {
		frameworks[report.Environment.Framework] = struct{}{}
	}

	toolSeen := map[string]struct{}{}
	networkSeen := map[string]struct{}{}
	shellSeen := map[string]struct{}{}
	credentialSeen := map[string]struct{}{}
	mcpSeen := map[string]struct{}{}
	manifestSeen := map[string]struct{}{}
	notebookSeen := map[string]struct{}{}

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if _, ignore := ignoreDiscoverDirs[d.Name()]; ignore {
				return filepath.SkipDir
			}
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || info.Size() > 1<<20 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !discoverableExtension(ext, filepath.Base(path)) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		report.Stats.FilesScanned++
		switch ext {
		case ".py":
			report.Stats.PythonFiles++
		case ".js", ".jsx", ".ts", ".tsx":
			report.Stats.NodeFiles++
		case ".json", ".jsonc":
			report.Stats.JSONFiles++
		case ".ipynb":
			notebookSeen[rel] = struct{}{}
		}

		base := filepath.Base(path)
		if base == "pyproject.toml" || strings.HasPrefix(base, "requirements") || base == "package.json" || base == "mcp.json" {
			manifestSeen[rel] = struct{}{}
		}

		bodyBytes, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		body := string(bodyBytes)
		lower := strings.ToLower(body)

		for _, framework := range detectFrameworksInText(lower) {
			frameworks[framework] = struct{}{}
		}
		if base == "mcp.json" || strings.Contains(body, `"mcpServers"`) || strings.Contains(body, `"mcp_servers"`) {
			mcpSeen[rel] = struct{}{}
			addDiscoveredTool(report, toolSeen, DiscoveredTool{ID: "tools/call", Surface: "mcp", Source: "mcp-config", File: rel})
		}
		if strings.Contains(lower, "tools/call") {
			addDiscoveredTool(report, toolSeen, DiscoveredTool{ID: "tools/call", Surface: "mcp", Source: "mcp-runtime", File: rel})
		}
		if strings.Contains(lower, "@tool") || strings.Contains(lower, "structuredtool") || strings.Contains(lower, "basetool") {
			addDiscoveredTool(report, toolSeen, DiscoveredTool{ID: "framework/tool", Surface: "framework-hook", Source: "framework-tool", File: rel})
		}
		for _, match := range toolLiteralRe.FindAllStringSubmatch(body, -1) {
			if len(match) < 2 {
				continue
			}
			surface := "tool"
			switch {
			case strings.Contains(match[1], "shell/"):
				surface = "shell"
			case strings.Contains(match[1], "http/"), strings.Contains(match[1], "proxy/"), strings.Contains(match[1], "net/"):
				surface = "network"
			case strings.Contains(match[1], "credential/"):
				surface = "credential"
			}
			addDiscoveredTool(report, toolSeen, DiscoveredTool{ID: match[1], Surface: surface, Source: "literal", File: rel})
		}
		if hasNetworkReference(lower) {
			networkSeen[rel] = struct{}{}
			for _, url := range urlLiteralRe.FindAllString(body, -1) {
				networkSeen[rel+"::"+url] = struct{}{}
			}
		}
		if hasShellReference(lower) {
			shellSeen[rel] = struct{}{}
			addDiscoveredTool(report, toolSeen, DiscoveredTool{ID: "shell/exec", Surface: "shell", Source: "static-signal", File: rel})
		}
		if hasCredentialReference(lower) {
			credentialSeen[rel] = struct{}{}
			addDiscoveredTool(report, toolSeen, DiscoveredTool{ID: "credential/broker", Surface: "credential", Source: "static-signal", File: rel})
		}
		return nil
	})

	report.Frameworks = sortedKeys(frameworks)
	report.MCPConfigFiles = sortedKeys(mcpSeen)
	report.ManifestFiles = sortedKeys(manifestSeen)
	report.NotebookFiles = sortedKeys(notebookSeen)
	report.NetworkReferences = sortedKeys(networkSeen)
	report.ShellReferences = sortedKeys(shellSeen)
	report.CredentialReferences = sortedKeys(credentialSeen)
	slices.SortFunc(report.CandidateTools, func(a, b DiscoveredTool) int {
		if a.ID != b.ID {
			return strings.Compare(a.ID, b.ID)
		}
		return strings.Compare(a.File, b.File)
	})
	return report
}

func discoverableExtension(ext, base string) bool {
	switch ext {
	case ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".md", ".ipynb":
		return true
	default:
		return base == "package.json" || base == "pyproject.toml" || strings.HasPrefix(base, "requirements")
	}
}

func detectFrameworksInText(lower string) []string {
	found := map[string]struct{}{}
	for token, framework := range nodeFrameworkTokens {
		if strings.Contains(lower, token) {
			found[framework] = struct{}{}
		}
	}
	for _, token := range []string{"langgraph", "langchain", "crewai", "pydantic-ai", "llama-index", "deepagents", "google-adk", "strands-agents", "bedrock-agentcore"} {
		if strings.Contains(lower, token) {
			found[token] = struct{}{}
		}
	}
	return sortedKeys(found)
}

func hasNetworkReference(lower string) bool {
	return strings.Contains(lower, "http://") ||
		strings.Contains(lower, "https://") ||
		strings.Contains(lower, "requests.") ||
		strings.Contains(lower, "httpx.") ||
		strings.Contains(lower, "fetch(") ||
		strings.Contains(lower, "axios.") ||
		strings.Contains(lower, "net/http")
}

func hasShellReference(lower string) bool {
	return strings.Contains(lower, "subprocess.") ||
		strings.Contains(lower, "os.system(") ||
		strings.Contains(lower, "shell=true") ||
		strings.Contains(lower, "child_process") ||
		strings.Contains(lower, "spawn(") ||
		strings.Contains(lower, "exec(")
}

func hasCredentialReference(lower string) bool {
	return strings.Contains(lower, "os.getenv(") ||
		strings.Contains(lower, "process.env") ||
		strings.Contains(lower, "secretmanager") ||
		strings.Contains(lower, "vault") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "access_token")
}

func addDiscoveredTool(report *DiscoveryReport, seen map[string]struct{}, tool DiscoveredTool) {
	key := tool.ID + "::" + tool.Source + "::" + tool.File
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	report.CandidateTools = append(report.CandidateTools, tool)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
