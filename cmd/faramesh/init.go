package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Detect your environment and generate Faramesh configuration",
	Long: `faramesh init auto-detects your environment (Python, Kubernetes, Docker,
Lambda, MCP) and outputs the exact configuration needed to get governed agents
running. Generates a policy skeleton and environment-specific setup files.`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().Bool("auto-detect", true, "auto-detect environment (default: true)")
}

func runInit(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.FgHiBlack)
	red := color.New(color.FgRed)

	bold.Printf("\nFaramesh %s — Unified Governance Plane\n", version)
	fmt.Println("Detecting your environment...")
	fmt.Println()

	env := detectEnvironment()

	for _, check := range env.checks {
		if check.found {
			green.Printf("  ✓ Detected: %s\n", check.label)
		} else if check.optional {
			dim.Printf("  ✗ %s (optional)\n", check.label)
		}
	}
	fmt.Println()

	fmt.Printf("Recommended adapter: ")
	bold.Printf("%s\n", env.adapter)
	dim.Printf("Reason: %s\n\n", env.reason)

	fmt.Println("Generating configuration...")
	fmt.Println()

	fmt.Println("  faramesh/")
	fmt.Println("    policy.yaml         ← Policy file (edit this)")

	switch env.adapterKey {
	case "k8s":
		fmt.Println("    faramesh-values.yaml ← Helm values for sidecar deployment")
		fmt.Println("    networkpolicy.yaml   ← K8s NetworkPolicy (recommended)")
	case "docker":
		fmt.Println("    docker-compose.yml  ← Compose snippet to add faramesh service")
	case "lambda":
		fmt.Println("    layer-config.json   ← Lambda Layer ARN + env var template")
	}

	fmt.Println()
	bold.Println("Next steps:")
	fmt.Println()

	switch env.adapterKey {
	case "python":
		fmt.Println("  1. Edit faramesh/policy.yaml — add your governance rules")
		fmt.Println("  2. faramesh policy validate faramesh/policy.yaml")
		bold.Println("  3. from faramesh import govern")
		bold.Println("     governed_tool = govern(my_tool, policy='faramesh/policy.yaml')")
		fmt.Println("  4. faramesh audit tail")
	case "k8s":
		fmt.Println("  1. Edit faramesh/policy.yaml")
		fmt.Println("  2. faramesh policy validate faramesh/policy.yaml")
		fmt.Println("  3. kubectl create configmap faramesh-policy --from-file=faramesh/policy.yaml")
		bold.Println("  4. helm install faramesh faramesh/faramesh-sidecar -f faramesh/faramesh-values.yaml")
		bold.Println("  5. kubectl label deployment my-agent faramesh.io/inject=true")
		fmt.Println("  6. faramesh audit tail")
	case "docker":
		fmt.Println("  1. Edit faramesh/policy.yaml")
		bold.Println("  2. faramesh run --policy faramesh/policy.yaml python agent.py")
	case "lambda":
		fmt.Println("  1. Edit faramesh/policy.yaml")
		fmt.Println("  2. Store policy in AWS SSM: aws ssm put-parameter ...")
		bold.Println("  3. Add Lambda layer, set FARAMESH_POLICY_SSM=/faramesh/policy")
	default:
		fmt.Println("  1. Edit faramesh/policy.yaml — add your governance rules")
		fmt.Println("  2. faramesh policy validate faramesh/policy.yaml")
		bold.Println("  3. faramesh serve --policy faramesh/policy.yaml")
		bold.Println("  4. from faramesh import govern")
		fmt.Println("  5. faramesh audit tail")
	}

	fmt.Println()
	yellow.Printf("Tip: ")
	fmt.Printf("Start in observation mode first:\n")
	bold.Printf("  faramesh serve --policy faramesh/policy.yaml\n")
	fmt.Println()
	fmt.Printf("Run the demo to see governance in action:\n")
	bold.Printf("  faramesh demo\n\n")

	if err := writeSkeletonPolicy(); err != nil {
		red.Printf("Warning: could not write policy skeleton: %v\n", err)
	} else {
		green.Printf("✓ Created faramesh/policy.yaml\n\n")
	}

	return nil
}

type envCheck struct {
	label    string
	found    bool
	optional bool
}

type envDetection struct {
	checks     []envCheck
	adapter    string
	adapterKey string
	reason     string
}

func detectEnvironment() envDetection {
	var checks []envCheck
	hasPython := commandExists("python3") || commandExists("python")
	hasNode := commandExists("node")
	hasKubectl := commandExists("kubectl")
	hasDocker := commandExists("docker")
	hasHelm := commandExists("helm")
	_, hasLambda := os.LookupEnv("AWS_LAMBDA_FUNCTION_NAME")
	_, hasMCP := os.LookupEnv("MCP_SERVER")

	checks = append(checks,
		envCheck{label: pythonLabel(), found: hasPython},
		envCheck{label: "Node.js agent", found: hasNode, optional: true},
		envCheck{label: "Kubernetes cluster (kubectl available)", found: hasKubectl, optional: true},
		envCheck{label: "Helm", found: hasHelm, optional: true},
		envCheck{label: "Docker", found: hasDocker, optional: true},
		envCheck{label: "AWS Lambda environment", found: hasLambda, optional: true},
		envCheck{label: "MCP server", found: hasMCP, optional: true},
		envCheck{label: fmt.Sprintf("eBPF / CAP_BPF (Linux 5.8+ only)"), found: false, optional: true},
	)

	var adapter, adapterKey, reason string
	switch {
	case hasKubectl:
		adapter = "A3 (Sidecar + Transparent Proxy)"
		adapterKey = "k8s"
		reason = "Kubernetes environment detected"
		if hasHelm {
			reason += "; Helm available for one-command deployment"
		}
	case hasLambda:
		adapter = "A4 (Serverless / Lambda Layer)"
		adapterKey = "lambda"
		reason = "AWS Lambda environment detected"
	case hasMCP:
		adapter = "A5 (MCP Gateway)"
		adapterKey = "mcp"
		reason = "MCP_SERVER environment variable detected"
	case hasDocker:
		adapter = "A2 (Local Daemon + Docker Compose)"
		adapterKey = "docker"
		reason = "Docker available; daemon runs as a compose service"
	default:
		adapter = "A1 (SDK Shim — zero infrastructure)"
		adapterKey = "python"
		reason = "No orchestration layer detected; SDK shim is the fastest path to governance"
	}

	return envDetection{checks: checks, adapter: adapter, adapterKey: adapterKey, reason: reason}
}

func pythonLabel() string {
	for _, cmd := range []string{"python3", "python"} {
		if commandExists(cmd) {
			out, err := exec.Command(cmd, "--version").CombinedOutput()
			if err == nil {
				return string(out[:len(out)-1]) + " agent"
			}
		}
	}
	return "Python agent"
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

const skeletonPolicy = `faramesh-version: '1.0'
agent-id: my-agent
default_effect: permit

vars:
  max_refund: 500

rules:
  # Deny destructive shell commands.
  - id: deny-destructive-shell
    match:
      tool: shell/run
      when: 'args["cmd"] matches "rm\\s+-[rf]" || args["cmd"] matches "mkfs"'
    effect: deny
    reason: destructive shell command blocked by policy
    reason_code: DESTRUCTIVE_SHELL_COMMAND

  # Require approval for high-value operations.
  - id: defer-high-value
    match:
      tool: stripe/refund
      when: 'args["amount"] > vars["max_refund"]'
    effect: defer
    reason: high-value operation requires human approval
    reason_code: HIGH_VALUE_THRESHOLD
`

func writeSkeletonPolicy() error {
	if err := os.MkdirAll("faramesh", 0o755); err != nil {
		return err
	}
	dest := "faramesh/policy.yaml"
	if _, err := os.Stat(dest); err == nil {
		return nil // don't overwrite existing policy
	}
	return os.WriteFile(dest, []byte(skeletonPolicy), 0o644)
}

var _ = runtime.GOOS // prevent import erasure
