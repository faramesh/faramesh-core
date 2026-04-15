package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

var attachCmd = &cobra.Command{
	Use:   "attach",
	Short: "Attach Faramesh in observe-first shadow mode to a project",
	Args:  cobra.NoArgs,
	RunE:  runAttachE,
}

var (
	attachJSON              bool
	attachCwd               string
	attachDataDir           string
	attachPolicyPath        string
	attachSocketPath        string
	attachObservationWindow time.Duration
	attachStartDaemon       bool
	attachInteractive       bool
)

type attachReport struct {
	Root              string                          `json:"root"`
	DataDir           string                          `json:"data_dir"`
	PolicyPath        string                          `json:"policy_path"`
	SocketPath        string                          `json:"socket_path"`
	ObservationWindow string                          `json:"observation_window"`
	Environment       *runtimeenv.DetectedEnvironment `json:"environment,omitempty"`
	Discovery         *runtimeenv.DiscoveryReport     `json:"discovery,omitempty"`
	Coverage          coverageReport                  `json:"coverage"`
	DaemonStarted     bool                            `json:"daemon_started"`
	DaemonLogPath     string                          `json:"daemon_log_path,omitempty"`
}

func init() {
	attachCmd.Flags().BoolVar(&attachJSON, "json", false, "print JSON")
	attachCmd.Flags().StringVar(&attachCwd, "cwd", "", "working directory to scan (default: current directory)")
	attachCmd.Flags().StringVar(&attachDataDir, "data-dir", "", "Faramesh data directory used for inventory and shadow bootstrap files")
	attachCmd.Flags().StringVar(&attachPolicyPath, "policy", "", "existing policy path to use instead of generating an observe-first shadow bootstrap policy")
	attachCmd.Flags().StringVar(&attachSocketPath, "socket", "", "daemon socket path (default: <data-dir>/faramesh-attach.sock)")
	attachCmd.Flags().DurationVar(&attachObservationWindow, "observation-window", 15*time.Second, "how long to observe before printing coverage")
	attachCmd.Flags().BoolVar(&attachStartDaemon, "start-daemon", true, "start a bounded shadow-mode daemon for the observation window")
	attachCmd.Flags().BoolVar(&attachInteractive, "interactive", true, "prompt before starting the shadow daemon when attached to a terminal")
}

func runAttachE(_ *cobra.Command, _ []string) error {
	cwd := attachCwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	dataDir := attachDataDir
	if strings.TrimSpace(dataDir) == "" {
		dataDir = filepath.Join(os.TempDir(), "faramesh")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	socketPath := strings.TrimSpace(attachSocketPath)
	if socketPath == "" {
		socketPath = filepath.Join(dataDir, "faramesh-attach.sock")
	}

	discovery := runtimeenv.DiscoverProject(cwd)
	policyPath, err := resolveAttachPolicyPath(cwd, dataDir, attachPolicyPath)
	if err != nil {
		return err
	}

	report := attachReport{
		Root:              cwd,
		DataDir:           dataDir,
		PolicyPath:        policyPath,
		SocketPath:        socketPath,
		ObservationWindow: attachObservationWindow.String(),
		Environment:       discovery.Environment,
		Discovery:         discovery,
		Coverage:          buildCoverageReport(cwd, dataDir, discovery, nil),
	}

	if attachStartDaemon {
		if attachInteractive && isInteractiveTerminal() {
			ok, promptErr := confirmAttachStart(cwd, attachObservationWindow, policyPath)
			if promptErr != nil {
				return promptErr
			}
			if !ok {
				return nil
			}
		}
		logPath, coverage, startErr := runAttachObservation(cwd, dataDir, socketPath, policyPath, discovery, attachObservationWindow)
		if startErr != nil {
			return startErr
		}
		report.DaemonStarted = true
		report.DaemonLogPath = logPath
		report.Coverage = coverage
	}

	if attachJSON {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", body)
		return nil
	}
	printAttachReport(report)
	return nil
}

func resolveAttachPolicyPath(cwd, dataDir, rawPath string) (string, error) {
	if policyPath, err := resolveOnboardPolicyPath(rawPath, cwd); err == nil {
		return policyPath, nil
	}
	policyPath := filepath.Join(dataDir, "attach-shadow-bootstrap.yaml")
	body := strings.TrimSpace(`
faramesh-version: "1.0"
agent-id: "attach-observe"
default_effect: permit
rules: []
`) + "\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		return "", fmt.Errorf("write attach bootstrap policy: %w", err)
	}
	return policyPath, nil
}

func runAttachObservation(cwd, dataDir, socketPath, policyPath string, discovery *runtimeenv.DiscoveryReport, window time.Duration) (string, coverageReport, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", coverageReport{}, fmt.Errorf("resolve current executable: %w", err)
	}
	logPath := filepath.Join(dataDir, "attach-daemon.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return "", coverageReport{}, fmt.Errorf("create attach log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(exe,
		"serve",
		"--policy", policyPath,
		"--mode", "shadow",
		"--data-dir", dataDir,
		"--socket", socketPath,
		"--skip-onboard-preflight",
	)
	cmd.Dir = cwd
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return "", coverageReport{}, fmt.Errorf("start shadow daemon: %w", err)
	}

	waitErr := waitForDaemonSocket(socketPath, 5*time.Second)
	if waitErr != nil {
		_ = stopAttachDaemon(cmd)
		return logPath, coverageReport{}, fmt.Errorf("shadow daemon did not become ready: %w", waitErr)
	}

	time.Sleep(window)

	store, err := toolinventory.OpenStore(filepath.Join(dataDir, "faramesh-tool-inventory.db"))
	if err != nil {
		_ = stopAttachDaemon(cmd)
		return logPath, coverageReport{}, fmt.Errorf("open tool inventory: %w", err)
	}
	entries, readErr := store.All()
	_ = store.Close()
	stopErr := stopAttachDaemon(cmd)
	if readErr != nil {
		return logPath, coverageReport{}, fmt.Errorf("read tool inventory: %w", readErr)
	}
	if stopErr != nil {
		return logPath, coverageReport{}, stopErr
	}
	return logPath, buildCoverageReport(cwd, dataDir, discovery, entries), nil
}

func waitForDaemonSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", socketPath)
}

func stopAttachDaemon(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		if err == nil {
			return nil
		}
		if strings.Contains(err.Error(), "signal: interrupt") {
			return nil
		}
		return err
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		err := <-done
		if err == nil || strings.Contains(err.Error(), "signal: killed") {
			return nil
		}
		return err
	}
}

func confirmAttachStart(cwd string, window time.Duration, policyPath string) (bool, error) {
	fmt.Printf("Attach plan:\n")
	fmt.Printf("  root              %s\n", cwd)
	fmt.Printf("  observation       %s\n", window)
	fmt.Printf("  shadow policy     %s\n", policyPath)
	fmt.Printf("Start shadow daemon now? [Y/n]: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "" || answer == "y" || answer == "yes", nil
}

func isInteractiveTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func printAttachReport(report attachReport) {
	fmt.Printf("Root:              %s\n", report.Root)
	fmt.Printf("Policy:            %s\n", report.PolicyPath)
	fmt.Printf("Socket:            %s\n", report.SocketPath)
	fmt.Printf("Observation:       %s\n", report.ObservationWindow)
	if report.Environment != nil {
		fmt.Printf("Runtime:           %s\n", report.Environment.Runtime)
		fmt.Printf("Framework Hint:    %s\n", report.Environment.Framework)
	}
	fmt.Printf("Discovered Tools:  %d\n", len(report.Discovery.CandidateTools))
	fmt.Printf("Observed Tools:    %d\n", report.Coverage.Summary.ObservedTools)
	if report.DaemonStarted {
		fmt.Printf("Daemon Log:        %s\n", report.DaemonLogPath)
	}
	fmt.Println()
	for _, tool := range report.Coverage.Tools {
		fmt.Printf("%-22s tier=%-2s source=%-7s calls=%d\n", tool.ToolID, tool.CoverageTier, tool.Source, tool.TotalInvocations)
	}
}
