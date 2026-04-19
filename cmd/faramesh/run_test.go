package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
)

func TestBuildRunEnv_nonEmptyCore(t *testing.T) {
	d := &runtimeenv.DetectedEnvironment{
		TrustLevel:   "linux_user_land",
		AdapterLevel: 1,
		Runtime:      "local",
		Framework:    "langchain",
	}
	e := buildRunEnv(d, "")
	s := strings.Join(e, " ")
	if !strings.Contains(s, "FARAMESH_SPAWNED_BY=faramesh-run") || !strings.Contains(s, "FARAMESH_TRUST_LEVEL=") {
		t.Fatal(s)
	}
}

func TestMergeEnv_override(t *testing.T) {
	base := []string{"FOO=1", "FARAMESH_TRUST_LEVEL=old"}
	extra := []string{"FARAMESH_TRUST_LEVEL=new"}
	out := mergeEnv(base, extra)
	if strings.Join(out, ";") != "FOO=1;FARAMESH_TRUST_LEVEL=new" {
		t.Fatalf("%v", out)
	}
}

func TestRunCmdJSON(t *testing.T) {
	root := findRepoRoot(t)
	cmd := exec.Command("go", "run", ".", "run", "--json")
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v", err)
	}
	var d runtimeenv.DetectedEnvironment
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if d.Runtime == "" || d.GoOS == "" {
		t.Fatalf("%+v", d)
	}
}

func TestStripAmbientCredentials(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/test",
		"OPENAI_API_KEY=sk-abc123",
		"OPENROUTER_API_KEY=or-key",
		"STRIPE_API_KEY=sk_live_456",
		"FARAMESH_STRIPE_SECRET_KEY=sk_faramesh",
		"FARAMESH_SOCKET=/tmp/faramesh.sock",
		"DATABASE_URL=postgres://localhost:5432/db",
		"MY_CUSTOM_VAR=keep",
	}
	out, stripped := stripAmbientCredentials(env)

	if len(stripped) != 5 {
		t.Fatalf("expected 5 stripped, got %d: %v", len(stripped), stripped)
	}
	for _, s := range stripped {
		if s != "OPENAI_API_KEY" && s != "OPENROUTER_API_KEY" && s != "STRIPE_API_KEY" && s != "FARAMESH_STRIPE_SECRET_KEY" && s != "DATABASE_URL" {
			t.Fatalf("unexpected strip: %s", s)
		}
	}

	for _, e := range out {
		k, _, _ := strings.Cut(e, "=")
		if k == "OPENAI_API_KEY" || k == "OPENROUTER_API_KEY" || k == "STRIPE_API_KEY" || k == "FARAMESH_STRIPE_SECRET_KEY" || k == "DATABASE_URL" {
			t.Fatalf("should have been stripped: %s", e)
		}
	}

	found := false
	for _, e := range out {
		if strings.HasPrefix(e, "MY_CUSTOM_VAR=") {
			found = true
		}
	}
	if !found {
		t.Fatal("MY_CUSTOM_VAR should be preserved")
	}
}

func TestResolveChildAgentID_ExplicitOverridesAndSanitizes(t *testing.T) {
	got := resolveChildAgentID(nil, "Stripe Agent 01", nil, "/tmp/repo", []string{"python", "agent.py"})
	if got != "stripe-agent-01" {
		t.Fatalf("resolveChildAgentID explicit = %q", got)
	}
}

func TestResolveChildAgentID_UsesEnvWhenPresent(t *testing.T) {
	env := []string{"FARAMESH_AGENT_ID=from-env"}
	got := resolveChildAgentID(env, "", nil, "/tmp/repo", []string{"python", "agent.py"})
	if got != "from-env" {
		t.Fatalf("resolveChildAgentID env = %q", got)
	}
}

func TestInferAgentID_FromPythonScript(t *testing.T) {
	got := inferAgentID(nil, "/tmp/repo", []string{"python3", "./agents/payments_agent.py"})
	if got != "payments_agent" {
		t.Fatalf("inferAgentID script = %q", got)
	}
}

func TestInferAgentID_FromPythonModule(t *testing.T) {
	got := inferAgentID(nil, "/tmp/repo", []string{"python", "-m", "company.agent.runner"})
	if got != "company.agent.runner" {
		t.Fatalf("inferAgentID module = %q", got)
	}
}

func TestInferFrameworkFromCommand_DeepAgentsScript(t *testing.T) {
	got := inferFrameworkFromCommand([]string{"python", "sdk/python/examples/deepagents_openrouter_qwen_production.py"})
	if got != "deepagents" {
		t.Fatalf("inferFrameworkFromCommand deepagents = %q", got)
	}
}

func TestInferFrameworkFromCommand_Module(t *testing.T) {
	got := inferFrameworkFromCommand([]string{"python", "-m", "langgraph.cli"})
	if got != "langgraph" {
		t.Fatalf("inferFrameworkFromCommand module = %q", got)
	}
}

func TestInferHarnessFromCommand_UsesFrameworkHint(t *testing.T) {
	got := inferHarnessFromCommand([]string{"python", "-m", "deepagents.cli"})
	if got != "deepagents" {
		t.Fatalf("inferHarnessFromCommand = %q", got)
	}
}

func TestResolveChildSocket_PrefersEnvWhenFlagUnchanged(t *testing.T) {
	oldDaemonSocket := daemonSocket
	defer func() { daemonSocket = oldDaemonSocket }()

	f := rootCmd.PersistentFlags().Lookup("daemon-socket")
	if f == nil {
		t.Fatal("daemon-socket flag missing")
	}
	oldChanged := f.Changed
	defer func() { f.Changed = oldChanged }()

	f.Changed = false
	daemonSocket = "/tmp/default.sock"
	got := resolveChildSocket([]string{"FARAMESH_SOCKET=/tmp/from-env.sock"})
	if got != "/tmp/from-env.sock" {
		t.Fatalf("resolveChildSocket env-preferred = %q", got)
	}
}

func TestResolveChildSocket_UsesFlagWhenProvided(t *testing.T) {
	oldDaemonSocket := daemonSocket
	defer func() { daemonSocket = oldDaemonSocket }()

	f := rootCmd.PersistentFlags().Lookup("daemon-socket")
	if f == nil {
		t.Fatal("daemon-socket flag missing")
	}
	oldChanged := f.Changed
	defer func() { f.Changed = oldChanged }()

	f.Changed = true
	daemonSocket = "/tmp/from-flag.sock"
	got := resolveChildSocket([]string{"FARAMESH_SOCKET=/tmp/from-env.sock"})
	if got != "/tmp/from-flag.sock" {
		t.Fatalf("resolveChildSocket flag-preferred = %q", got)
	}
}

func TestResolveChildSocket_UsesRuntimeStateWhenFlagAndEnvUnset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	tmpSocketFile, err := os.CreateTemp("/tmp", "fmrt-*.sock")
	if err != nil {
		t.Fatalf("create temp socket path: %v", err)
	}
	runtimeSocket := tmpSocketFile.Name()
	_ = tmpSocketFile.Close()
	_ = os.Remove(runtimeSocket)
	defer os.Remove(runtimeSocket)

	ln, err := net.Listen("unix", runtimeSocket)
	if err != nil {
		t.Fatalf("listen runtime socket: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(`{"status":"ok"}`))
			}(conn)
		}
	}()

	runtimeDir := filepath.Join(home, ".faramesh", "runtime")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := writeRuntimeStartState(filepath.Join(runtimeDir, "runtime.json"), runtimeStartState{SocketPath: runtimeSocket}); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	oldDaemonSocket := daemonSocket
	defer func() { daemonSocket = oldDaemonSocket }()
	daemonSocket = sdk.SocketPath

	f := rootCmd.PersistentFlags().Lookup("daemon-socket")
	if f == nil {
		t.Fatal("daemon-socket flag missing")
	}
	oldChanged := f.Changed
	defer func() { f.Changed = oldChanged }()
	f.Changed = false

	got := resolveChildSocket(nil)
	if got != runtimeSocket {
		t.Fatalf("resolveChildSocket runtime-preferred = %q", got)
	}
}

func TestResolveChildSocket_DefaultsToHomeRuntimeSocket(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldDaemonSocket := daemonSocket
	defer func() { daemonSocket = oldDaemonSocket }()
	daemonSocket = ""

	f := rootCmd.PersistentFlags().Lookup("daemon-socket")
	if f == nil {
		t.Fatal("daemon-socket flag missing")
	}
	oldChanged := f.Changed
	defer func() { f.Changed = oldChanged }()
	f.Changed = false

	got := resolveChildSocket(nil)
	want := filepath.Join(home, ".faramesh", "runtime", "faramesh.sock")
	if got != want {
		t.Fatalf("resolveChildSocket default = %q, want %q", got, want)
	}
}

func TestResolveAutoStartPolicyPath_UsesRuntimeState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	runtimeDir := filepath.Join(home, ".faramesh", "runtime")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	want := "/tmp/runtime-policy.fpl"
	if err := writeRuntimeStartState(filepath.Join(runtimeDir, "runtime.json"), runtimeStartState{PolicyPath: want}); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	got := resolveAutoStartPolicyPath("")
	if got != want {
		t.Fatalf("resolveAutoStartPolicyPath = %q, want %q", got, want)
	}
}

func TestEnforcementReport_trustLevel(t *testing.T) {
	r := &enforcementReport{
		autoload:        true,
		credentialStrip: []string{"OPENAI_API_KEY"},
	}
	// Without OS layers, trust level stays as whatever was passed
	if r.trustLevel != "" {
		t.Fatalf("expected empty trust level before enforcement, got %q", r.trustLevel)
	}
}

func TestShouldEnforce(t *testing.T) {
	if shouldEnforce("none") {
		t.Fatal("none should not enforce")
	}
	if !shouldEnforce("auto") {
		t.Fatal("auto should enforce")
	}
	if !shouldEnforce("full") {
		t.Fatal("full should enforce")
	}
}

func TestBestEffortRequested(t *testing.T) {
	oldBestEffort := runBestEffort
	oldAllowReduced := runAllowReducedGovernance
	defer func() {
		runBestEffort = oldBestEffort
		runAllowReducedGovernance = oldAllowReduced
	}()

	runBestEffort = false
	runAllowReducedGovernance = false
	if bestEffortRequested() {
		t.Fatal("bestEffortRequested should be false when no flags are set")
	}

	runBestEffort = true
	runAllowReducedGovernance = false
	if !bestEffortRequested() {
		t.Fatal("bestEffortRequested should be true when --best-effort is set")
	}

	runBestEffort = false
	runAllowReducedGovernance = true
	if !bestEffortRequested() {
		t.Fatal("bestEffortRequested should be true when --allow-reduced-governance is set")
	}
}

func TestExplicitReducedEnforcementRequested(t *testing.T) {
	oldRunEnforce := runEnforce
	defer func() { runEnforce = oldRunEnforce }()

	runEnforce = "auto"
	if explicitReducedEnforcementRequested() {
		t.Fatal("auto should not request explicit reduced enforcement")
	}

	runEnforce = "minimal"
	if !explicitReducedEnforcementRequested() {
		t.Fatal("minimal should request explicit reduced enforcement")
	}

	runEnforce = "none"
	if !explicitReducedEnforcementRequested() {
		t.Fatal("none should request explicit reduced enforcement")
	}
}

func TestFormatGovernanceBlockedErrorIncludesRemediation(t *testing.T) {
	err := formatGovernanceBlockedError(os.ErrNotExist)
	msg := err.Error()
	if !strings.Contains(msg, "governance: blocked") {
		t.Fatalf("blocked error missing governance header: %q", msg)
	}
	if !strings.Contains(msg, "Remediation") {
		t.Fatalf("blocked error missing remediation guidance: %q", msg)
	}
	if !strings.Contains(msg, "--best-effort") {
		t.Fatalf("blocked error missing explicit best-effort guidance: %q", msg)
	}
}

func TestLooksLikePythonCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "python binary", args: []string{"python", "agent.py"}, want: true},
		{name: "python3 binary", args: []string{"python3", "-m", "app"}, want: true},
		{name: "script entrypoint", args: []string{"./agent.py"}, want: true},
		{name: "non python", args: []string{"node", "agent.js"}, want: false},
		{name: "empty", args: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := looksLikePythonCommand(tc.args)
			if got != tc.want {
				t.Fatalf("looksLikePythonCommand(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestPrependPathListEnv(t *testing.T) {
	base := []string{"PATH=/usr/bin", "PYTHONPATH=/x:/y"}
	out := prependPathListEnv(base, "PYTHONPATH", "/sdk")
	got := envValue(out, "PYTHONPATH")
	if got != "/sdk"+string(os.PathListSeparator)+"/x:/y" {
		t.Fatalf("unexpected PYTHONPATH: %q", got)
	}

	out2 := prependPathListEnv(out, "PYTHONPATH", "/sdk")
	got2 := envValue(out2, "PYTHONPATH")
	if got2 != got {
		t.Fatalf("expected idempotent prepend, got %q want %q", got2, got)
	}
}

func TestResolvePythonSDKPathFromEnv(t *testing.T) {
	sdkDir := t.TempDir()
	t.Setenv("FARAMESH_PYTHON_SDK_PATH", sdkDir)

	got, ok := resolvePythonSDKPath()
	if !ok {
		t.Fatal("expected sdk path resolution from env override")
	}

	abs, err := filepath.Abs(sdkDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if got != abs {
		t.Fatalf("resolvePythonSDKPath = %q, want %q", got, abs)
	}
}

func TestResolvePythonSDKPathDoesNotAutoDiscoverLocalRepo(t *testing.T) {
	t.Setenv("FARAMESH_PYTHON_SDK_PATH", "")

	got, ok := resolvePythonSDKPath()
	if ok {
		t.Fatalf("resolvePythonSDKPath should not auto-discover repo paths, got %q", got)
	}
}

func TestProxyReady(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	if !proxyReady(port) {
		t.Fatalf("proxyReady(%d) = false, want true", port)
	}
	if proxyReady(port + 1) {
		t.Fatalf("proxyReady(%d) = true, want false", port+1)
	}
}
