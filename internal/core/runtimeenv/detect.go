package runtimeenv

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// DetectedEnvironment summarizes runtime, harness, framework, and enforcement hints.
// Fields are best-effort; empty string means unknown / not detected.
type DetectedEnvironment struct {
	Framework    string `json:"framework"`
	Runtime      string `json:"runtime"`
	AgentHarness string `json:"agent_harness"`
	IDE          string `json:"ide"`
	AdapterLevel int    `json:"adapter_level"`
	TrustLevel   string `json:"trust_level"`
	GoOS         string `json:"goos"`
}

// DetectEnvironment inspects process environment and files under cwd.
func DetectEnvironment(cwd string) *DetectedEnvironment {
	env := &DetectedEnvironment{}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	env.GoOS = runtime.GOOS
	env.Runtime = classifyRuntime()
	env.IDE = detectIDE(cwd)
	env.AgentHarness = detectAgentHarness(cwd)
	deps := ScanPythonDeps(cwd)
	env.Framework = detectFramework(deps)

	env.AdapterLevel = determineAdapterLevel(env)
	env.TrustLevel = determineTrustLevel(env)
	return env
}

// ToJSON returns a stable JSON representation for CLI and tests.
func (e *DetectedEnvironment) ToJSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// RuntimeKind returns the env-derived runtime classification (matches DetectedEnvironment.Runtime).
func RuntimeKind() string {
	return classifyRuntime()
}

func classifyRuntime() string {
	switch {
	case os.Getenv("KUBERNETES_SERVICE_HOST") != "":
		return "k8s"
	case os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "":
		return "lambda"
	case os.Getenv("AWS_BEDROCK_AGENT_ID") != "" || os.Getenv("BEDROCK_AGENTCORE_RUNTIME_ARN") != "":
		return "bedrock-agentcore"
	case os.Getenv("GOOGLE_CLOUD_PROJECT") != "" && os.Getenv("VERTEX_AGENT") != "":
		return "vertex"
	case os.Getenv("MODAL_TASK_ID") != "":
		return "modal"
	case os.Getenv("DATABRICKS_RUNTIME_VERSION") != "":
		return "databricks"
	case os.Getenv("CLOUD_RUN_JOB") != "" || os.Getenv("K_SERVICE") != "":
		return "cloud-run"
	default:
		return "local"
	}
}

func detectIDE(cwd string) string {
	switch {
	case os.Getenv("CURSOR_TRACE_ID") != "" || os.Getenv("CURSOR_AGENT") != "":
		return "cursor"
	case os.Getenv("VSCODE_INJECTION") != "" || os.Getenv("TERM_PROGRAM") == "vscode":
		return "vscode"
	case os.Getenv("ZED_TERM") != "" || os.Getenv("ZED_PID") != "":
		return "zed"
	case os.Getenv("Windsurf") != "":
		return "windsurf"
	default:
		if fileExists(filepath.Join(cwd, ".cursorrules")) || dirExists(filepath.Join(cwd, ".cursor")) {
			return "cursor"
		}
		return ""
	}
}

func detectAgentHarness(cwd string) string {
	switch {
	case dirExists(filepath.Join(cwd, ".openclaw")):
		return "openclaw"
	case dirExists(filepath.Join(cwd, ".deepagents")):
		return "deepagents-cli"
	case binaryExists("claude") && dirExists(filepath.Join(cwd, ".claude")):
		return "claude-code"
	case binaryExists("codex") && fileExists(filepath.Join(cwd, "AGENTS.md")):
		return "codex-cli"
	case binaryExists("gemini") && fileExists(filepath.Join(cwd, "GEMINI.md")):
		return "gemini-cli"
	case dirExists(filepath.Join(cwd, ".kiro")):
		return "kiro"
	case dirExists(filepath.Join(cwd, ".windsurf")):
		return "windsurf"
	case binaryExists("aider"):
		return "aider"
	case dirExists(filepath.Join(cwd, ".continue")):
		return "continue"
	default:
		return ""
	}
}

func detectFramework(deps *PythonDeps) string {
	if deps == nil {
		return ""
	}
	switch {
	case deps.Has("deepagents"):
		return "deepagents"
	case deps.Has("langgraph"):
		return "langgraph"
	case deps.Has("langchain") || deps.Has("langchain-core"):
		return "langchain"
	case deps.Has("crewai"):
		return "crewai"
	case deps.Has("pyautogen") || deps.Has("autogen") || deps.Has("autogen-agentchat"):
		return "autogen"
	case deps.Has("semantic-kernel"):
		return "semantic-kernel"
	case deps.Has("pydantic-ai"):
		return "pydantic-ai"
	case deps.Has("llama-index") || deps.Has("llama-index-core"):
		return "llamaindex"
	case deps.Has("smolagents"):
		return "smolagents"
	case deps.Has("haystack-ai") || deps.Has("haystack"):
		return "haystack"
	case deps.Has("google-adk"):
		return "google-adk"
	case deps.Has("strands-agents") || deps.Has("strands-agents-builder"):
		return "strands-agents"
	case deps.Has("bedrock-agentcore"):
		return "bedrock-agentcore"
	default:
		return ""
	}
}

func determineAdapterLevel(e *DetectedEnvironment) int {
	level := 0
	if e.Runtime != "" {
		level = 1
	}
	if e.Framework != "" || e.AgentHarness != "" {
		if level < 2 {
			level = 2
		}
	}
	// Network redirect / namespace story is plausible on local Linux and k8s sidecars.
	if e.Runtime == "k8s" || e.Runtime == "local" {
		if level < 3 {
			level = 3
		}
	}
	if os.Getenv("FARAMESH_ISOLATION") == "microvm" {
		level = 4
	}
	if v := os.Getenv("FARAMESH_ADAPTER_LEVEL"); v != "" {
		// Operator override for CI and staged rollouts.
		switch v {
		case "4":
			return 4
		case "3":
			return 3
		case "2":
			return 2
		case "1":
			return 1
		case "0":
			return 0
		}
	}
	return level
}

func determineTrustLevel(e *DetectedEnvironment) string {
	if os.Getenv("FARAMESH_TRUST_LEVEL") != "" {
		return os.Getenv("FARAMESH_TRUST_LEVEL")
	}
	if os.Getenv("FARAMESH_ISOLATION") == "microvm" {
		return "maximum"
	}
	switch e.Runtime {
	case "lambda", "bedrock", "bedrock-agentcore", "vertex":
		return "credential_only"
	case "modal", "databricks":
		return "partial"
	case "cloud-run":
		return "partial"
	case "k8s":
		return "strong"
	default:
		return "strong"
	}
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// ApplyFarameshEnv sets FARAMESH_* hints for a child process based on detection.
// Note: FARAMESH_FRAMEWORK_HINT is informational only — the Python autopatch
// layer does not branch on it; it tries all registered patchers regardless.
// The hint is useful for logging, diagnostics, and external tooling.
func ApplyFarameshEnv(dst []string, det *DetectedEnvironment, policyPath string) []string {
	out := append([]string(nil), dst...)
	set := func(k, v string) {
		if v == "" {
			return
		}
		prefix := k + "="
		for i, e := range out {
			if strings.HasPrefix(e, prefix) {
				out[i] = prefix + v
				return
			}
		}
		out = append(out, prefix+v)
	}
	if det == nil {
		det = &DetectedEnvironment{}
	}
	set("FARAMESH_TRUST_LEVEL", det.TrustLevel)
	set("FARAMESH_ADAPTER_LEVEL", strconv.Itoa(det.AdapterLevel))
	set("FARAMESH_RUNTIME_KIND", det.Runtime)
	set("FARAMESH_FRAMEWORK_HINT", det.Framework)
	set("FARAMESH_AGENT_HARNESS", det.AgentHarness)
	set("FARAMESH_IDE_HINT", det.IDE)
	if policyPath != "" {
		set("FARAMESH_POLICY_PATH", policyPath)
	}
	return out
}
