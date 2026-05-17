package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/governance"
)

func ensureDaemonStartedFromCompiled(stackDir string, compiled *governance.Compiled) (daemonStartResult, error) {
	if compiled == nil {
		return daemonStartResult{}, fmt.Errorf("nil compiled stack")
	}
	stateDir, err := resolveRuntimeStateDir("")
	if err != nil {
		return daemonStartResult{}, err
	}
	compiledPath, err := filepath.Abs(governance.CompiledPath(stackDir))
	if err != nil {
		return daemonStartResult{}, err
	}
	socketPath := compiled.Daemon.SocketPath
	dataDir := compiled.Daemon.DataDir
	policyPath := compiled.Daemon.PolicyPath
	mode := compiled.Daemon.RuntimeMode

	pidPath := filepath.Join(stateDir, "daemon.pid")
	logPath := filepath.Join(stateDir, "daemon.log")
	metaPath := filepath.Join(stateDir, "runtime.json")

	if pid, alive := readPIDState(pidPath); alive {
		if socketStatusOK(socketPath) {
			// Running daemon: restart with new compiled config.
			_ = terminatePID(pid)
			_ = os.Remove(pidPath)
			_ = os.Remove(socketPath)
		}
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return daemonStartResult{}, fmt.Errorf("create data dir: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return daemonStartResult{}, err
	}

	args := []string{
		"serve",
		"--from-compiled", compiledPath,
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return daemonStartResult{}, err
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
		return daemonStartResult{}, err
	}

	state := runtimeStartState{
		PolicyPath: policyPath,
		SocketPath: socketPath,
		DataDir:    dataDir,
		Mode:       strings.TrimSpace(mode),
		DaemonPID:  daemonPID,
		LogPath:    logPath,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	_ = writeRuntimeStartState(metaPath, state)

	if err := waitForSocketReady(socketPath, 8*time.Second); err != nil {
		return daemonStartResult{}, fmt.Errorf("daemon started (pid=%d) but socket not ready: %w", daemonPID, err)
	}

	return daemonStartResult{
		State:      state,
		StateDir:   stateDir,
		PIDPath:    pidPath,
		MetaPath:   metaPath,
		AlreadyRunning: false,
	}, nil
}
