package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

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
  faramesh run --policy p.yaml -- python a.py  # with explicit policy
  faramesh run --enforce full -- python a.py   # all layers`,
	Args: cobra.ArbitraryArgs,
	RunE: runRunE,
}

var (
	runJSON     bool
	runPolicy   string
	runEnforce  string
	runBrokerOn bool
	runNoSeccomp bool
	runNoLandlock bool
	runNoNetns   bool
	runWorkspace string
)

func init() {
	runCmd.Flags().BoolVar(&runJSON, "json", false, "print DetectedEnvironment as JSON")
	runCmd.Flags().StringVar(&runPolicy, "policy", "", "policy path (set FARAMESH_POLICY_PATH)")
	runCmd.Flags().StringVar(&runEnforce, "enforce", "auto", "enforcement level: auto|full|minimal|none")
	runCmd.Flags().BoolVar(&runBrokerOn, "broker", false, "enable credential broker (strip ambient API keys)")
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

	name, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	env := buildRunEnv(det, policyPath)

	report := &enforcementReport{}

	if shouldEnforce(runEnforce) {
		env = applyEnforcementStack(det, env, cwd, report)
	}

	printEnforcementReport(det, report)

	return syscallExec(name, args, env)
}

type enforcementReport struct {
	autoload       bool
	credentialStrip []string
	seccomp        bool
	seccompErr     error
	landlock       bool
	landlockErr    error
	netns          bool
	netnsErr       error
	proxyEnv       bool
	proxyEnvMethod string
	trustLevel     string
}

func shouldEnforce(level string) bool {
	return level != "none"
}

func applyEnforcementStack(det *runtimeenv.DetectedEnvironment, env []string, cwd string, r *enforcementReport) []string {
	// L1: Framework auto-patch (inject FARAMESH_AUTOLOAD=1 so Python/Node hooks activate)
	env = mergeEnv(env, []string{"FARAMESH_AUTOLOAD=1"})
	r.autoload = true

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
		// macOS: proxy env vars for network interception (no entitlement needed).
		proxyVars := sandbox.ProxyEnvVars(18443)
		env = mergeEnv(env, proxyVars)
		r.proxyEnv = true
		if os.Geteuid() == 0 {
			r.proxyEnvMethod = "PF + proxy env vars"
		} else {
			r.proxyEnvMethod = "proxy env vars (HTTP_PROXY/HTTPS_PROXY)"
		}

	case "windows":
		// Windows: proxy env vars. WinDivert kernel interception with admin.
		proxyVars := sandbox.ProxyEnvVars(18443)
		env = mergeEnv(env, proxyVars)
		r.proxyEnv = true
		r.proxyEnvMethod = "proxy env vars (WinDivert available with admin)"

	default:
		// Unknown OS — proxy env vars as universal fallback.
		proxyVars := sandbox.ProxyEnvVars(18443)
		env = mergeEnv(env, proxyVars)
		r.proxyEnv = true
		r.proxyEnvMethod = "proxy env vars"
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
		"STRIPE_API_KEY", "STRIPE_SECRET_KEY",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"GITHUB_TOKEN", "GH_TOKEN",
		"SLACK_TOKEN", "SLACK_BOT_TOKEN",
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

	check("Framework auto-patch (FARAMESH_AUTOLOAD)", r.autoload, nil)
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
