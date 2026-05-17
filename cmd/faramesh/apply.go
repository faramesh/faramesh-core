package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/governance"
	"github.com/faramesh/faramesh-core/internal/security"
)

var (
	applyCmd = &cobra.Command{
		Use:   "apply",
		Short: "Compile governance.fms and start or reload the runtime",
		Long: `Runs check, compiles governance.fms to governance.compiled.json, materializes
governance.policy.fpl, and starts the governance daemon. Use --stop to shut down
the runtime without recompiling.`,
		Args: cobra.NoArgs,
		RunE: runApply,
	}
	applyStop            bool
	applyCheckUID        bool
	applyRequireUIDSep   bool
)

func init() {
	applyCmd.Flags().StringVar(&stackDirFlag, "dir", "", "stack directory (default: current working directory)")
	applyCmd.Flags().BoolVar(&applyStop, "stop", false, "stop the governance daemon")
	applyCmd.Flags().BoolVar(&applyCheckUID, "check-uid", false, "print UID separation status and continue")
	applyCmd.Flags().BoolVar(&applyRequireUIDSep, "require-uid-separation", false, "fail apply if production UID separation is not satisfied")
}

func runApply(_ *cobra.Command, _ []string) error {
	if applyStop {
		return runStop(nil, nil)
	}

	stackDir, err := resolveStackDir()
	if err != nil {
		return err
	}
	path, content, err := governance.FindSource(stackDir)
	if err != nil {
		return err
	}
	doc, _, err := governance.LoadDocument(stackDir)
	if err != nil {
		return err
	}
	diags := governance.Check(doc, governance.CheckOptions{RequireEnv: true})
	if len(diags) > 0 {
		governance.PrintDiagnostics(os.Stderr, diags)
	}
	if governance.HasErrors(diags) {
		return fmt.Errorf("check failed")
	}
	if applyCheckUID {
		res := security.CheckUIDSeparation()
		fmt.Printf("→ UID check: current=%s daemon_user=%v agent_user=%v separation_ok=%v\n",
			res.CurrentUser, res.DaemonUserOK, res.AgentUserOK, res.SeparationOK)
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
		}
	}
	if err := security.EnforceUIDSeparation(applyRequireUIDSep); err != nil {
		return err
	}
	if err := governance.ResolveProviderImports(doc, stackDir, false); err != nil {
		return fmt.Errorf("provider import download failed: %w", err)
	}
	governance.WireProviderSources(doc, stackDir)
	compiled, compileDiags, err := governance.Compile(doc, stackDir, content, governance.CompileOptions{CheckEnv: true})
	if len(compileDiags) > 0 {
		governance.PrintDiagnostics(os.Stderr, compileDiags)
	}
	if err != nil {
		return err
	}
	if err := compiled.Write(stackDir); err != nil {
		return err
	}
	printCompiledOK()
	_ = path

	result, err := ensureDaemonStartedFromCompiled(stackDir, compiled)
	if err != nil {
		return err
	}
	if result.AlreadyRunning {
		fmt.Printf("→ runtime reloaded (pid=%d)\n", result.State.DaemonPID)
	} else {
		fmt.Printf("→ runtime started (pid=%d)\n", result.State.DaemonPID)
	}
	fmt.Printf("→ Unix socket: %s\n", result.State.SocketPath)
	return nil
}
