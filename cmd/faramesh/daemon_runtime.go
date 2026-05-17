package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
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

type daemonStartResult struct {
	State          runtimeStartState
	StateDir       string
	PIDPath        string
	MetaPath       string
	AlreadyRunning bool
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
		dir = runtimeStateDirPath("")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create runtime state dir: %w", err)
	}
	return dir, nil
}

func readPIDState(path string) (int, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}
	if runtime.GOOS == "windows" {
		err = proc.Signal(syscall.Signal(0))
		return pid, err == nil
	}
	err = proc.Signal(syscall.Signal(0))
	return pid, err == nil
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

func runFaramesh(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func detectDefaultPolicyPath() string {
	candidates := []string{
		"governance.policy.fpl",
		"governance.fms",
		"faramesh/policy.fpl",
		"policy.fpl",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
			return p
		}
	}
	return ""
}

func isProcessPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied")
}
