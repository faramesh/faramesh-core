package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/faramesh/faramesh-core/internal/core/governance"
	"github.com/faramesh/faramesh-core/internal/devmode"
	"github.com/spf13/cobra"
)

var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Run a local governance stack with stub providers and in-memory WAL",
	Long:  "Compiles governance.fms, stubs absent providers, and starts the daemon for local development.",
	RunE:  runDev,
}

var devStackDir string

func init() {
	devCmd.Flags().StringVar(&devStackDir, "dir", ".", "stack directory containing governance.fms")
}

func runDev(cmd *cobra.Command, _ []string) error {
	stackDir, err := filepath.Abs(devStackDir)
	if err != nil {
		return err
	}
	doc, _, err := governance.LoadDocument(stackDir)
	if err != nil {
		return err
	}
	diags := governance.Check(doc, governance.CheckOptions{})
	if governance.HasErrors(diags) {
		governance.PrintDiagnostics(os.Stderr, diags)
		return fmt.Errorf("governance check failed")
	}
	_, content, err := governance.FindSource(stackDir)
	if err != nil {
		return err
	}
	compiled, diags, err := governance.Compile(doc, stackDir, content, governance.CompileOptions{})
	if governance.HasErrors(diags) {
		governance.PrintDiagnostics(os.Stderr, diags)
	}
	if err != nil {
		return err
	}
	if err := compiled.Write(stackDir); err != nil {
		return err
	}

	cfg := compiled.ToDaemonConfig()
	devmode.Apply(&cfg, stackDir)
	if cfg.Log == nil {
		log, err := buildLogger("info")
		if err != nil {
			return err
		}
		cfg.Log = log
	}
	cfg.DevMode = true

	fmt.Println("✓ governance.fms compiled")
	fmt.Println("✓ in-process providers stubbed: vault (dev server), spiffe (ephemeral CA), kms (ephemeral RSA)")
	fmt.Println("✓ WAL: in-memory")
	fmt.Println("✓ enforcement: application-tier only (OS enforcement not active in dev mode)")
	fmt.Printf("→ Unix socket: %s\n", cfg.SocketPath)
	mcpPort := mcpProxyPort(compiled)
	if mcpPort > 0 {
		fmt.Printf("→ MCP proxy: http://127.0.0.1:%d/mcp\n", mcpPort)
	}
	fmt.Println("→ status: faramesh status")
	fmt.Println("→ approvals: faramesh approvals list")
	printDevPlatformNote()

	serveFromCompiled = governance.CompiledPath(stackDir)
	_ = os.Setenv("FARAMESH_DEV_MODE", "1")
	return runServeWithConfig(cmd, cfg)
}

func mcpProxyPort(compiled *governance.Compiled) int {
	if compiled == nil || compiled.Agents == nil {
		return 0
	}
	for _, spec := range compiled.Agents {
		if spec.MCPProxyPort > 0 {
			return spec.MCPProxyPort
		}
	}
	return 0
}

func printDevPlatformNote() {
	fmt.Println()
	switch runtime.GOOS {
	case "linux":
		return
	case "windows":
		fmt.Println("Note: seccomp/Landlock not available on windows. Network proxy enforcement is active. Production deployments on Linux provide full enforcement.")
	default:
		fmt.Println("Note: seccomp/Landlock not available on darwin. Production deployments on Linux provide full enforcement.")
	}
}
