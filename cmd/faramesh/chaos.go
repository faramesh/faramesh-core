package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	chaosDataDir string
	chaosPID     int
)

var (
	chaosFindDaemonPID = findDaemonPID
	chaosSendSignal    = func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
)

var chaosCmd = &cobra.Command{
	Use:   "chaos-test",
	Short: "Trigger daemon fault/degraded chaos toggles",
}

var chaosDegradedCmd = &cobra.Command{
	Use:   "degraded [toggle|on|off]",
	Short: "Toggle forced degraded mode on the running daemon",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runChaosDegraded,
}

var chaosFaultCmd = &cobra.Command{
	Use:   "fault [toggle|on|off]",
	Short: "Toggle fault-injection mode on the running daemon",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runChaosFault,
}

func init() {
	chaosCmd.PersistentFlags().StringVar(&chaosDataDir, "data-dir", "", "daemon data directory for PID lookup (default: $TMPDIR/faramesh)")
	chaosCmd.PersistentFlags().IntVar(&chaosPID, "pid", 0, "override daemon PID (skips PID file lookup)")
	chaosCmd.AddCommand(chaosDegradedCmd)
	chaosCmd.AddCommand(chaosFaultCmd)
}

func runChaosDegraded(_ *cobra.Command, args []string) error {
	action := parseChaosAction(args)
	pid, err := resolveChaosPID()
	if err != nil {
		return err
	}
	return dispatchChaosAction(pid, action, syscall.SIGUSR1)
}

func runChaosFault(_ *cobra.Command, args []string) error {
	action := parseChaosAction(args)
	pid, err := resolveChaosPID()
	if err != nil {
		return err
	}
	return dispatchChaosAction(pid, action, syscall.SIGUSR2)
}

func parseChaosAction(args []string) string {
	if len(args) == 0 {
		return "toggle"
	}
	return strings.ToLower(strings.TrimSpace(args[0]))
}

func resolveChaosPID() (int, error) {
	if chaosPID > 0 {
		return chaosPID, nil
	}
	dataDir := strings.TrimSpace(chaosDataDir)
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), "faramesh")
	}
	pid, err := chaosFindDaemonPID(dataDir)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func dispatchChaosAction(pid int, action string, sig syscall.Signal) error {
	switch action {
	case "toggle":
		return chaosSendSignal(pid, sig)
	case "on":
		if err := chaosSendSignal(pid, sig); err != nil {
			return err
		}
		if err := chaosSendSignal(pid, sig); err != nil {
			return err
		}
		return nil
	case "off":
		if err := chaosSendSignal(pid, sig); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported action %q (use toggle|on|off)", action)
	}
}

func findDaemonPID(dataDir string) (int, error) {
	pidPath := filepath.Join(dataDir, "faramesh.pid")
	raw, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, fmt.Errorf("read daemon pid file %q: %w", pidPath, err)
	}
	pidStr := strings.TrimSpace(string(raw))
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid daemon pid %q in %q", pidStr, pidPath)
	}
	return pid, nil
}
