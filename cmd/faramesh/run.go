package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
	"github.com/faramesh/faramesh-core/internal/core/sandbox"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Exec a child process under Faramesh governance with full enforcement stack",
	Long: `Detects runtime, framework, and agent harness. Installs the strongest
enforcement layers available in the current environment, then replaces the
process with the child command.

Enforcement layers activated automatically when available:
  L1  Framework auto-patch (FARAMESH_AUTOLOAD=1 in child env)
  L3  Network namespace + iptables REDIRECT (Linux + root)
  L4  Credential broker (strips ambient API keys from env)
  L5  seccomp-BPF (immutable syscall filter, Linux)
  L6  Landlock LSM (filesystem allowlist, Linux 5.13+)
  L9  Faramesh policy engine (via FARAMESH_SOCKET)

Usage:
  faramesh run --json                       # print detection only
  faramesh run -- python agent.py           # govern + exec
	faramesh run --policy p.fpl -- python a.py   # with explicit policy
  faramesh run --enforce full -- python a.py   # all layers`,
	Args: cobra.ArbitraryArgs,
	RunE: runRunE,
}

var (
	runJSON       bool
	runPolicy     string
	runEnforce    string
	runBrokerOn   bool
	runAutoStart  bool
	runAutoMode   string
	runAgentID    string
	runNoSeccomp  bool
	runNoLandlock bool
	runNoNetns    bool
	runWorkspace  string
)

func init() {
	runCmd.Flags().BoolVar(&runJSON, "json", false, "print DetectedEnvironment as JSON")
	runCmd.Flags().StringVar(&runPolicy, "policy", "", "policy path (set FARAMESH_POLICY_PATH)")
	runCmd.Flags().StringVar(&runEnforce, "enforce", "auto", "enforcement level: auto|full|minimal|none")
	runCmd.Flags().BoolVar(&runBrokerOn, "broker", false, "enable credential broker (strip ambient API keys)")
	runCmd.Flags().BoolVar(&runAutoStart, "auto-start", true, "auto-start runtime daemon when socket is unreachable")
	runCmd.Flags().StringVar(&runAutoMode, "auto-start-mode", "enforce", "daemon mode used by --auto-start: enforce|shadow|audit")
	runCmd.Flags().StringVar(&runAgentID, "agent-id", "", "agent identity injected as FARAMESH_AGENT_ID (default: inferred from command)")
	runCmd.Flags().BoolVar(&runNoSeccomp, "no-seccomp", false, "skip seccomp-BPF installation")
	runCmd.Flags().BoolVar(&runNoLandlock, "no-landlock", false, "skip Landlock filesystem restrictions")
	runCmd.Flags().BoolVar(&runNoNetns, "no-netns", false, "skip network namespace isolation")
	runCmd.Flags().StringVar(&runWorkspace, "workspace", "", "workspace directory for Landlock (default: cwd)")
}

func runRunE(_ *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}
	det := runtimeenv.DetectEnvironment(cwd)

	if runJSON && len(args) == 0 {
		b, err := det.ToJSON()
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", b)
		return nil
	}
	if len(args) == 0 {
		return fmt.Errorf("missing command: use faramesh run -- <command> [args...], or faramesh run --json for detection only")
	}

	if det.Framework == "" {
		det.Framework = inferFrameworkFromCommand(args)
	}
	if det.AgentHarness == "" {
		det.AgentHarness = inferHarnessFromCommand(args)
	}

	policyPath := strings.TrimSpace(runPolicy)
	if policyPath != "" {
		if abs, err := filepath.Abs(policyPath); err == nil {
			policyPath = abs
		}
	}

	if runJSON {
		b, err := det.ToJSON()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s\n", b)
	}

	childSocket := resolveChildSocket(os.Environ())
	if !socketStatusOK(childSocket) {
		if !runAutoStart {
			return fmt.Errorf("daemon socket %s is not reachable (run faramesh up or faramesh start first)", childSocket)
		}

		autoPolicyPath := policyPath
		if strings.TrimSpace(autoPolicyPath) == "" {
			autoPolicyPath = detectDefaultPolicyPath()
			if strings.TrimSpace(autoPolicyPath) == "" {
				return fmt.Errorf("daemon socket %s is not reachable and no local policy file was found for auto-start; provide --policy or run faramesh up --policy <path>", childSocket)
			}
		}

		result, err := ensureDaemonStarted(daemonStartOptions{
			PolicyPath: autoPolicyPath,
			Mode:       runAutoMode,
			SocketPath: childSocket,
		})
		if err != nil {
			return fmt.Errorf("auto-start runtime: %w", err)
		}
		if result.AlreadyRunning {
			fmt.Fprintf(os.Stderr, "Faramesh runtime detected on %s (pid=%d)\n", result.State.SocketPath, result.State.DaemonPID)
		} else {
			fmt.Fprintf(os.Stderr, "Faramesh runtime auto-started on %s (pid=%d)\n", result.State.SocketPath, result.State.DaemonPID)
		}
	}

	if runBrokerOn || runEnforce == "full" {
		if err := ensureBrokerModeReady(childSocket); err != nil {
			return err
		}
	}

	name, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	env := buildRunEnv(det, policyPath)

	report := &enforcementReport{}
	env = applyRunRuntimeWiring(env, det, cwd, args, report)

	if shouldEnforce(runEnforce) {
		env = applyEnforcementStack(det, env, cwd, args, report)
	}

	printEnforcementReport(det, report)

	return syscallExec(name, args, env)
}

type enforcementReport struct {
	autoload                bool
	childSocket             string
	childAgentID            string
	pythonAutoloadAttempted bool
	pythonAutoloadPath      string
	credentialStrip         []string
	seccomp                 bool
	seccompErr              error
	landlock                bool
	landlockErr             error
	netns                   bool
	netnsErr                error
	proxyEnv                bool
	proxyEnvMethod          string
	trustLevel              string
}

type brokerModeDiagnostics struct {
	RouterConfigured bool                       `json:"router_configured"`
	Backends         []string                   `json:"backends"`
	FallbackBackend  string                     `json:"fallback_backend"`
	ToolCount        int                        `json:"tool_count"`
	Tools            []brokerModeToolDiagnostic `json:"tools"`
}

type brokerModeToolDiagnostic struct {
	ToolID        string `json:"tool_id"`
	BrokerEnabled bool   `json:"broker_enabled"`
	Backend       string `json:"backend"`
	UsesFallback  bool   `json:"uses_fallback"`
}

func ensureBrokerModeReady(socketPath string) error {
	raw, err := daemonSocketRequestAt(socketPath, map[string]any{
		"type": "credential",
		"op":   "broker_map",
	})
	if err != nil {
		if daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
			raw, err = daemonGet("/api/v1/credential/map")
		}
		if err != nil {
			return fmt.Errorf("broker mode readiness check failed: %w", err)
		}
	}

	var diag brokerModeDiagnostics
	if err := json.Unmarshal(raw, &diag); err != nil {
		return fmt.Errorf("broker mode readiness returned invalid diagnostics: %w", err)
	}

	if !diag.RouterConfigured {
		return fmt.Errorf("broker mode requested but credential router is not configured on the runtime")
	}

	if len(diag.Backends) == 0 {
		return fmt.Errorf("broker mode requested but no credential backends are registered")
	}

	envFallback := strings.EqualFold(strings.TrimSpace(diag.FallbackBackend), "env")
	offenders := make([]string, 0)
	for _, tool := range diag.Tools {
		if !tool.BrokerEnabled {
			continue
		}
		if tool.UsesFallback && strings.EqualFold(strings.TrimSpace(tool.Backend), "env") {
			offenders = append(offenders, tool.ToolID)
		}
	}

	if envFallback && len(offenders) > 0 {
		return fmt.Errorf("broker mode blocked: env fallback is active for broker-enabled tools (%s); configure non-env credential routes/backends before running with --broker", strings.Join(offenders, ", "))
	}

	return nil
}

func applyRunRuntimeWiring(env []string, det *runtimeenv.DetectedEnvironment, cwd string, childArgs []string, r *enforcementReport) []string {
	socketPath := resolveChildSocket(env)
	if socketPath != "" {
		env = mergeEnv(env, []string{"FARAMESH_SOCKET=" + socketPath})
		r.childSocket = socketPath
	}

	agentID := resolveChildAgentID(env, runAgentID, det, cwd, childArgs)
	if agentID != "" {
		env = mergeEnv(env, []string{"FARAMESH_AGENT_ID=" + agentID})
		r.childAgentID = agentID
	}

	return env
}

func resolveChildSocket(env []string) string {
	envSocket := strings.TrimSpace(envValue(env, "FARAMESH_SOCKET"))
	if envSocket != "" {
		if f := rootCmd.PersistentFlags().Lookup("daemon-socket"); f == nil || !f.Changed {
			return envSocket
		}
	}

	if socket := strings.TrimSpace(daemonSocket); socket != "" {
		return socket
	}
	if envSocket != "" {
		return envSocket
	}
	return sdk.SocketPath
}

func resolveChildAgentID(env []string, explicit string, det *runtimeenv.DetectedEnvironment, cwd string, childArgs []string) string {
	if id := sanitizeAgentID(explicit); id != "" {
		return id
	}
	if id := strings.TrimSpace(envValue(env, "FARAMESH_AGENT_ID")); id != "" {
		return id
	}
	id := inferAgentID(det, cwd, childArgs)
	if id == "" {
		return "agent"
	}
	return id
}

func inferAgentID(det *runtimeenv.DetectedEnvironment, cwd string, childArgs []string) string {
	candidates := make([]string, 0, 6)
	if det != nil {
		candidates = append(candidates, det.AgentHarness)
	}

	for i, arg := range childArgs {
		trimmed := strings.TrimSpace(arg)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if trimmed == "-m" && i+1 < len(childArgs) {
			candidates = append(candidates, childArgs[i+1])
			continue
		}
		if strings.HasSuffix(lower, ".py") {
			base := filepath.Base(trimmed)
			candidates = append(candidates, strings.TrimSuffix(base, filepath.Ext(base)))
		}
	}

	if len(childArgs) > 0 {
		exe := strings.TrimSpace(filepath.Base(childArgs[0]))
		if exe != "" && !strings.Contains(strings.ToLower(exe), "python") {
			candidates = append(candidates, strings.TrimSuffix(exe, filepath.Ext(exe)))
		}
	}

	candidates = append(candidates, filepath.Base(cwd))
	for _, candidate := range candidates {
		if id := sanitizeAgentID(candidate); id != "" {
			return id
		}
	}

	return "agent"
}

func inferFrameworkFromCommand(args []string) string {
	for i, arg := range args {
		trimmed := strings.TrimSpace(strings.ToLower(arg))
		if trimmed == "" {
			continue
		}

		if trimmed == "-m" && i+1 < len(args) {
			module := strings.TrimSpace(strings.ToLower(args[i+1]))
			switch {
			case strings.HasPrefix(module, "deepagents"):
				return "deepagents"
			case strings.Contains(module, "langgraph"):
				return "langgraph"
			case strings.Contains(module, "langchain"):
				return "langchain"
			}
		}

		switch {
		case strings.Contains(trimmed, "deepagents"):
			return "deepagents"
		case strings.Contains(trimmed, "langgraph"):
			return "langgraph"
		case strings.Contains(trimmed, "langchain"):
			return "langchain"
		}
	}

	return ""
}

func inferHarnessFromCommand(args []string) string {
	framework := inferFrameworkFromCommand(args)
	if framework == "" {
		return ""
	}
	return framework
}

func sanitizeAgentID(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(raw))
	lastDash := false
	for _, r := range raw {
		keep := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if keep {
			if r == '-' {
				if lastDash {
					continue
				}
				lastDash = true
			} else {
				lastDash = false
			}
			b.WriteRune(r)
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	clean := strings.Trim(b.String(), "-._")
	if clean == "" {
		return ""
	}
	return clean
}

func shouldEnforce(level string) bool {
	return level != "none"
}

func applyEnforcementStack(det *runtimeenv.DetectedEnvironment, env []string, cwd string, childArgs []string, r *enforcementReport) []string {
	// L1: Framework auto-patch (inject FARAMESH_AUTOLOAD=1 so Python/Node hooks activate)
	env = mergeEnv(env, []string{"FARAMESH_AUTOLOAD=1"})
	r.autoload = true

	// Python bootstrap: make sure startup hook is importable for source checkouts.
	if looksLikePythonCommand(childArgs) {
		r.pythonAutoloadAttempted = true
		if sdkPath, ok := resolvePythonSDKPath(cwd); ok {
			env = prependPathListEnv(env, "PYTHONPATH", sdkPath)
			r.pythonAutoloadPath = sdkPath
		}
	}

	// Node bootstrap: inject NODE_OPTIONS so MCP servers get auto-patched.
	if looksLikeNodeCommand(childArgs) {
		if autopatchPath, ok := resolveNodeAutopatchPath(cwd); ok {
			env = prependNodeOptions(env, autopatchPath)
		}
	}

	// L4: Credential broker — strip ambient API keys from child environment.
	if runBrokerOn || runEnforce == "full" {
		env, r.credentialStrip = stripAmbientCredentials(env)
	}

	// OS-level enforcement — platform-specific layers.
	switch runtime.GOOS {
	case "linux":
		isRoot := os.Geteuid() == 0

		// L5: seccomp-BPF (immutable syscall filter).
		if !runNoSeccomp && runEnforce != "minimal" {
			cfg := &sandbox.SandboxConfig{}
			r.seccompErr = sandbox.InstallSeccompFilter(cfg)
			r.seccomp = r.seccompErr == nil
		}

		// L6: Landlock filesystem restrictions.
		if !runNoLandlock && runEnforce != "minimal" {
			ws := cwd
			if runWorkspace != "" {
				ws = runWorkspace
			}
			cfg := &sandbox.SandboxConfig{ReadOnlyRoot: false}
			rules := sandbox.PolicyToLandlockRules(cfg, []string{ws})
			r.landlockErr = sandbox.ApplyLandlockRules(rules)
			r.landlock = r.landlockErr == nil
		}

		// L3: Network namespace + iptables REDIRECT (requires root).
		if !runNoNetns && isRoot && (runEnforce == "full" || runEnforce == "auto") {
			nsCfg := sandbox.NetNSConfig{
				Name:      fmt.Sprintf("faramesh-%d", os.Getpid()),
				ProxyPort: 18443,
			}
			r.netnsErr = sandbox.SetupNetworkNamespace(nsCfg)
			r.netns = r.netnsErr == nil
		}

	case "darwin":
		// macOS: inject proxy env vars only when a local Faramesh proxy listener is reachable.
		// This avoids breaking outbound model calls when no proxy adapter is running.
		if proxyReady(18443) {
			proxyVars := sandbox.ProxyEnvVars(18443)
			env = mergeEnv(env, proxyVars)
			r.proxyEnv = true
			if os.Geteuid() == 0 {
				r.proxyEnvMethod = "PF + proxy env vars"
			} else {
				r.proxyEnvMethod = "proxy env vars (HTTP_PROXY/HTTPS_PROXY)"
			}
		} else {
			r.proxyEnvMethod = "proxy listener not detected; env injection skipped"
		}

	case "windows":
		// Windows: inject proxy env vars only when listener is available.
		if proxyReady(18443) {
			proxyVars := sandbox.ProxyEnvVars(18443)
			env = mergeEnv(env, proxyVars)
			r.proxyEnv = true
			r.proxyEnvMethod = "proxy env vars (WinDivert available with admin)"
		} else {
			r.proxyEnvMethod = "proxy listener not detected; env injection skipped"
		}

	default:
		// Unknown OS — use proxy env vars only when listener is available.
		if proxyReady(18443) {
			proxyVars := sandbox.ProxyEnvVars(18443)
			env = mergeEnv(env, proxyVars)
			r.proxyEnv = true
			r.proxyEnvMethod = "proxy env vars"
		} else {
			r.proxyEnvMethod = "proxy listener not detected; env injection skipped"
		}
	}

	// Compute trust level based on what succeeded.
	switch {
	case r.seccomp && r.landlock && r.netns:
		r.trustLevel = "STRONG"
	case r.seccomp || r.landlock:
		r.trustLevel = "MODERATE"
	case r.proxyEnv && len(r.credentialStrip) > 0:
		r.trustLevel = "PARTIAL"
	case len(r.credentialStrip) > 0:
		r.trustLevel = "CREDENTIAL_ONLY"
	default:
		r.trustLevel = det.TrustLevel
	}

	env = mergeEnv(env, []string{
		"FARAMESH_TRUST_LEVEL=" + r.trustLevel,
	})
	return env
}

// stripAmbientCredentials removes well-known API key environment variables
// from the child process environment. The agent must request credentials
// through the Faramesh broker instead.
func stripAmbientCredentials(env []string) ([]string, []string) {
	ambientKeys := []string{
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
		"OPENROUTER_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY", "PERPLEXITY_API_KEY",
		"LANGSMITH_API_KEY", "HUGGINGFACEHUB_API_TOKEN", "HF_TOKEN",
		"STRIPE_API_KEY", "STRIPE_SECRET_KEY",
		"FARAMESH_STRIPE_SECRET_KEY",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"GITHUB_TOKEN", "GH_TOKEN",
		"SLACK_TOKEN", "SLACK_BOT_TOKEN",
		"TWILIO_ACCOUNT_SID",
		"TWILIO_AUTH_TOKEN", "SENDGRID_API_KEY",
		"DATABASE_URL", "REDIS_URL",
		"OPENCLAW_OPENAI_KEY", "OPENCLAW_ANTHROPIC_KEY",
	}

	var stripped []string
	out := make([]string, 0, len(env))
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			out = append(out, e)
			continue
		}
		found := false
		for _, ak := range ambientKeys {
			if strings.EqualFold(k, ak) {
				stripped = append(stripped, k)
				found = true
				break
			}
		}
		if !found {
			out = append(out, e)
		}
	}
	return out, stripped
}

func printEnforcementReport(det *runtimeenv.DetectedEnvironment, r *enforcementReport) {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	bold.Fprintf(os.Stderr, "\nFaramesh Enforcement Report\n")
	fmt.Fprintf(os.Stderr, "  Runtime:     %s\n", det.Runtime)
	if det.Framework != "" {
		fmt.Fprintf(os.Stderr, "  Framework:   %s\n", det.Framework)
	}
	if det.AgentHarness != "" {
		fmt.Fprintf(os.Stderr, "  Harness:     %s\n", det.AgentHarness)
	}
	fmt.Fprintln(os.Stderr)

	check := func(name string, ok bool, err error) {
		if ok {
			green.Fprintf(os.Stderr, "  ✓ %s\n", name)
		} else if err != nil {
			yellow.Fprintf(os.Stderr, "  ○ %s (unavailable: %v)\n", name, err)
		} else {
			red.Fprintf(os.Stderr, "  ✗ %s (skipped)\n", name)
		}
	}

	if r.childSocket != "" {
		green.Fprintf(os.Stderr, "  ✓ Daemon socket wiring (FARAMESH_SOCKET=%s)\n", r.childSocket)
	}
	if r.childAgentID != "" {
		green.Fprintf(os.Stderr, "  ✓ Agent identity wiring (FARAMESH_AGENT_ID=%s)\n", r.childAgentID)
	}

	check("Framework auto-patch (FARAMESH_AUTOLOAD)", r.autoload, nil)
	if r.pythonAutoloadPath != "" {
		green.Fprintf(os.Stderr, "  ✓ Python startup hook bootstrap (PYTHONPATH=%s)\n", r.pythonAutoloadPath)
	} else if r.pythonAutoloadAttempted {
		yellow.Fprintf(os.Stderr, "  ○ Python startup hook path not detected (set FARAMESH_PYTHON_SDK_PATH or install faramesh-sdk)\n")
	}
	if len(r.credentialStrip) > 0 {
		green.Fprintf(os.Stderr, "  ✓ Credential broker (stripped: %s)\n", strings.Join(r.credentialStrip, ", "))
	}
	if runtime.GOOS == "linux" {
		check("seccomp-BPF (immutable)", r.seccomp, r.seccompErr)
		check("Landlock LSM (filesystem)", r.landlock, r.landlockErr)
		check("Network namespace (iptables)", r.netns, r.netnsErr)
	}
	if r.proxyEnv {
		green.Fprintf(os.Stderr, "  ✓ Network interception (%s)\n", r.proxyEnvMethod)
	} else if r.proxyEnvMethod != "" {
		yellow.Fprintf(os.Stderr, "  ○ Network interception (%s)\n", r.proxyEnvMethod)
	}

	fmt.Fprintln(os.Stderr)
	bold.Fprintf(os.Stderr, "  Trust level: %s\n\n", r.trustLevel)
}

// buildRunEnv merges detection into the current environment.
func buildRunEnv(d *runtimeenv.DetectedEnvironment, policyPath string) []string {
	base := os.Environ()
	e := runtimeenv.ApplyFarameshEnv(base, d, policyPath)
	return mergeEnv(e, []string{"FARAMESH_SPAWNED_BY=faramesh-run"})
}

func mergeEnv(base, extra []string) []string {
	out := append([]string(nil), base...)
	for _, add := range extra {
		k, _, ok := strings.Cut(add, "=")
		if !ok {
			out = append(out, add)
			continue
		}
		replaced := false
		for i, ex := range out {
			if ek, _, ok2 := strings.Cut(ex, "="); ok2 && ek == k {
				out[i] = add
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, add)
		}
	}
	return out
}

func looksLikePythonCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	cmd := strings.ToLower(filepath.Base(args[0]))
	if strings.Contains(cmd, "python") {
		return true
	}
	for i := 0; i < len(args) && i < 3; i++ {
		if strings.HasSuffix(strings.ToLower(args[i]), ".py") {
			return true
		}
	}
	return false
}

func proxyReady(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func resolvePythonSDKPath(cwd string) (string, bool) {
	if override := strings.TrimSpace(os.Getenv("FARAMESH_PYTHON_SDK_PATH")); override != "" {
		if abs, err := filepath.Abs(override); err == nil {
			override = abs
		}
		if dirExists(override) {
			return override, true
		}
	}

	candidates := []string{
		filepath.Join(cwd, "faramesh-core", "sdk", "python"),
		filepath.Join(cwd, "sdk", "python"),
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "sdk", "python"),
			filepath.Join(exeDir, "..", "sdk", "python"),
			filepath.Join(exeDir, "..", "..", "sdk", "python"),
		)
	}

	for _, candidate := range candidates {
		if abs, err := filepath.Abs(candidate); err == nil {
			candidate = abs
		}
		if dirExists(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func prependPathListEnv(env []string, key, value string) []string {
	cur := envValue(env, key)
	if cur == "" {
		return mergeEnv(env, []string{key + "=" + value})
	}
	for _, p := range filepath.SplitList(cur) {
		if p == value {
			return env
		}
	}
	return mergeEnv(env, []string{key + "=" + value + string(os.PathListSeparator) + cur})
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix)
		}
	}
	return ""
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func looksLikeNodeCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	cmd := strings.ToLower(filepath.Base(args[0]))
	switch cmd {
	case "node", "npx", "tsx", "ts-node":
		return true
	}
	for i := 0; i < len(args) && i < 3; i++ {
		lower := strings.ToLower(args[i])
		if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".mjs") {
			return true
		}
	}
	return false
}

func resolveNodeAutopatchPath(cwd string) (string, bool) {
	if override := strings.TrimSpace(os.Getenv("FARAMESH_NODE_AUTOPATCH_PATH")); override != "" {
		if abs, err := filepath.Abs(override); err == nil {
			override = abs
		}
		if fileExists(override) {
			return override, true
		}
	}

	candidates := []string{
		filepath.Join(cwd, "faramesh-core", "sdk", "node", "dist", "autopatch.js"),
		filepath.Join(cwd, "sdk", "node", "dist", "autopatch.js"),
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "sdk", "node", "dist", "autopatch.js"),
			filepath.Join(exeDir, "..", "sdk", "node", "dist", "autopatch.js"),
			filepath.Join(exeDir, "..", "..", "sdk", "node", "dist", "autopatch.js"),
		)
	}

	for _, candidate := range candidates {
		if abs, err := filepath.Abs(candidate); err == nil {
			candidate = abs
		}
		if fileExists(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func prependNodeOptions(env []string, autopatchPath string) []string {
	requireFlag := "--require " + autopatchPath
	cur := envValue(env, "NODE_OPTIONS")
	if strings.Contains(cur, autopatchPath) {
		return env
	}
	if cur == "" {
		return mergeEnv(env, []string{"NODE_OPTIONS=" + requireFlag})
	}
	return mergeEnv(env, []string{"NODE_OPTIONS=" + requireFlag + " " + cur})
}
