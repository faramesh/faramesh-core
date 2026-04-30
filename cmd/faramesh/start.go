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
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type runtimeStartState struct {
	PolicyPath string               `json:"policy_path"`
	SocketPath string               `json:"socket_path"`
	DataDir    string               `json:"data_dir"`
	Mode       string               `json:"mode"`
	DaemonPID  int                  `json:"daemon_pid"`
	LogPath    string               `json:"log_path"`
	Visibility *managedServiceState `json:"visibility,omitempty"`
	Dashboard  *managedServiceState `json:"dashboard,omitempty"`
	UpdatedAt  string               `json:"updated_at"`
}

type managedServiceState struct {
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
	Managed bool   `json:"managed"`
	PID     int    `json:"pid,omitempty"`
	URL     string `json:"url,omitempty"`
	LogPath string `json:"log_path,omitempty"`
	Error   string `json:"error,omitempty"`
}

type daemonStartOptions struct {
	PolicyPath string
	Mode       string
	SocketPath string
	DataDir    string
	StateDir   string
}

type daemonStartResult struct {
	State              runtimeStartState
	StateDir           string
	PIDPath            string
	MetaPath           string
	AlreadyRunning     bool
	BootstrappedPolicy bool
}

var (
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Start Faramesh runtime",
		RunE:  runStart,
	}

	startPolicy   string
	startMode     string
	startSocket   string
	startDataDir  string
	startStateDir string
)

func init() {
	startCmd.Flags().StringVar(&startPolicy, "policy", "", "policy path (auto-detected when omitted)")
	startCmd.Flags().StringVar(&startMode, "mode", "enforce", "runtime mode: enforce|shadow|audit")
	startCmd.Flags().StringVar(&startSocket, "socket", "", "daemon Unix socket path (defaults to --daemon-socket)")
	startCmd.Flags().StringVar(&startDataDir, "data-dir", "", "daemon data directory")
	startCmd.Flags().StringVar(&startStateDir, "state-dir", "", "runtime state directory")
	_ = startCmd.Flags().MarkHidden("socket")
	_ = startCmd.Flags().MarkHidden("data-dir")
	_ = startCmd.Flags().MarkHidden("state-dir")
}

func runStart(_ *cobra.Command, _ []string) error {
	result, err := ensureDaemonStarted(daemonStartOptions{
		PolicyPath: startPolicy,
		Mode:       startMode,
		SocketPath: startSocket,
		DataDir:    startDataDir,
		StateDir:   startStateDir,
	})
	if err != nil {
		return err
	}

	if result.AlreadyRunning {
		fmt.Printf("runtime already running (pid=%d)\n", result.State.DaemonPID)
		fmt.Printf("socket: %s\n", result.State.SocketPath)
		return nil
	}

	fmt.Println("faramesh runtime started")
	fmt.Printf("daemon pid: %d\n", result.State.DaemonPID)
	fmt.Printf("socket: %s\n", result.State.SocketPath)
	fmt.Printf("policy: %s\n", result.State.PolicyPath)
	if result.BootstrappedPolicy {
		fmt.Printf("policy bootstrap: created starter policy at %s\n", result.State.PolicyPath)
	}
	fmt.Printf("mode: %s\n", result.State.Mode)
	fmt.Printf("log: %s\n", result.State.LogPath)
	return nil
}

func ensureDaemonStarted(opts daemonStartOptions) (daemonStartResult, error) {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = "enforce"
	}
	if mode != "enforce" && mode != "shadow" && mode != "audit" {
		return daemonStartResult{}, fmt.Errorf("invalid --mode %q (expected enforce|shadow|audit)", mode)
	}

	stateDir, err := resolveRuntimeStateDir(opts.StateDir)
	if err != nil {
		return daemonStartResult{}, err
	}

	policyPath := strings.TrimSpace(opts.PolicyPath)
	bootstrappedPolicy := false
	if policyPath == "" {
		policyPath = detectDefaultPolicyPath()
		if policyPath == "" {
			generatedPath, created, err := ensureBootstrapPolicy(stateDir)
			if err != nil {
				return daemonStartResult{}, err
			}
			policyPath = generatedPath
			bootstrappedPolicy = created
		}
	}
	absPolicyPath, err := filepath.Abs(policyPath)
	if err != nil {
		return daemonStartResult{}, fmt.Errorf("resolve policy path: %w", err)
	}

	socketPath := strings.TrimSpace(opts.SocketPath)
	if socketPath == "" {
		socketPath = resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
	}
	if socketPath == "" {
		socketPath = defaultDaemonSocketPath()
	}

	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(stateDir, "data")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return daemonStartResult{}, fmt.Errorf("create data dir: %w", err)
	}

	pidPath := filepath.Join(stateDir, "daemon.pid")
	logPath := filepath.Join(stateDir, "daemon.log")
	metaPath := filepath.Join(stateDir, "runtime.json")

	if pid, alive := readPIDState(pidPath); alive {
		if socketStatusOK(socketPath) {
			state := runtimeStartState{
				PolicyPath: absPolicyPath,
				SocketPath: socketPath,
				DataDir:    dataDir,
				Mode:       mode,
				DaemonPID:  pid,
				LogPath:    logPath,
				UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
			}
			_ = writeRuntimeStartState(metaPath, state)
			return daemonStartResult{
				State:              state,
				StateDir:           stateDir,
				PIDPath:            pidPath,
				MetaPath:           metaPath,
				AlreadyRunning:     true,
				BootstrappedPolicy: bootstrappedPolicy,
			}, nil
		}
		if err := terminatePID(pid); err != nil {
			return daemonStartResult{}, fmt.Errorf("stale runtime detected (pid=%d) but failed to stop: %w", pid, err)
		}
		_ = os.Remove(pidPath)
		_ = os.Remove(socketPath)
	}

	exe, err := os.Executable()
	if err != nil {
		return daemonStartResult{}, fmt.Errorf("resolve executable: %w", err)
	}

	args := []string{
		"serve",
		"--policy", absPolicyPath,
		"--socket", socketPath,
		"--data-dir", dataDir,
		"--mode", mode,
	}

	if profile, profileErr := loadRuntimeProfile(); profileErr == nil {
		args = applyCredentialProfileToServeArgs(args, profile)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return daemonStartResult{}, fmt.Errorf("open daemon log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command(exe, args...)
	applyProcessGroup(cmd)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return daemonStartResult{}, fmt.Errorf("start daemon: %w", err)
	}
	daemonPID := cmd.Process.Pid
	_ = cmd.Process.Release()

	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", daemonPID)), 0o644); err != nil {
		return daemonStartResult{}, fmt.Errorf("write daemon pid: %w", err)
	}

	state := runtimeStartState{
		PolicyPath: absPolicyPath,
		SocketPath: socketPath,
		DataDir:    dataDir,
		Mode:       mode,
		DaemonPID:  daemonPID,
		LogPath:    logPath,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeRuntimeStartState(metaPath, state); err != nil {
		return daemonStartResult{}, err
	}

	if err := waitForSocketReady(socketPath, 8*time.Second); err != nil {
		return daemonStartResult{}, fmt.Errorf("daemon started (pid=%d) but socket not ready: %w", daemonPID, err)
	}

	return daemonStartResult{
		State:              state,
		StateDir:           stateDir,
		PIDPath:            pidPath,
		MetaPath:           metaPath,
		AlreadyRunning:     false,
		BootstrappedPolicy: bootstrappedPolicy,
	}, nil
}

func ensureBootstrapPolicy(stateDir string) (string, bool, error) {
	path := filepath.Join(stateDir, "policy.bootstrap.yaml")
	if _, err := os.Stat(path); err == nil {
		return path, false, nil
	} else if !os.IsNotExist(err) {
		return "", false, fmt.Errorf("check starter policy path: %w", err)
	}

	starter := strings.TrimSpace(`faramesh-version: '1.0'
agent-id: starter-agent
default_effect: permit
rules: []
`) + "\n"
	if err := os.WriteFile(path, []byte(starter), 0o600); err != nil {
		return "", false, fmt.Errorf("write starter policy: %w", err)
	}
	return path, true, nil
}

func writeRuntimeStartState(path string, state runtimeStartState) error {
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o600)
}

func readRuntimeStartState(path string) (runtimeStartState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return runtimeStartState{}, err
	}
	var state runtimeStartState
	if err := json.Unmarshal(raw, &state); err != nil {
		return runtimeStartState{}, err
	}
	return state, nil
}

func resolveRuntimeStateDir(raw string) (string, error) {
	dir := strings.TrimSpace(raw)
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			dir = filepath.Join(os.TempDir(), "faramesh", "runtime")
		} else {
			dir = filepath.Join(home, ".faramesh", "runtime")
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create runtime state dir: %w", err)
	}
	return dir, nil
}

func detectDefaultPolicyPath() string {
	candidates := []string{
		"faramesh/policy.fpl",
		"policies/default.fpl",
		"faramesh/policy.yaml",
		"policy.yaml",
		"policy.fpl",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, absErr := filepath.Abs(p)
			if absErr != nil {
				return p
			}
			return abs
		}
	}
	return ""
}

func waitForSocketReady(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if socketStatusOK(socketPath) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not become ready before timeout", socketPath)
}

func socketStatusOK(socketPath string) bool {
	if strings.TrimSpace(socketPath) == "" {
		return false
	}
	conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write([]byte("{\"type\":\"status\"}\n")); err != nil {
		return false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	return err == nil && n > 0
}

func terminatePID(pid int) error {
	if pid <= 0 {
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return proc.Kill()
	}
	if terminated, err := terminateProcessGroup(pid); terminated {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if isProcessGoneError(err) {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !isProcessAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return proc.Kill()
}


func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		err = proc.Signal(syscall.Signal(0))
		return err == nil || isProcessPermissionError(err)
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || isProcessPermissionError(err)
}

func isProcessGoneError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "no such process") || strings.Contains(msg, "process already finished")
}

func isProcessPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied")
}
