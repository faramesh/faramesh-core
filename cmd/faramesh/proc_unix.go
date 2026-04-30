//go:build !windows

package main

import (
	"os/exec"
	"syscall"
	"time"
)

func applyProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateProcessGroup(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		if isProcessGoneError(err) {
			return false, nil
		}
		return false, err
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !isProcessGroupAlive(pid) {
			return true, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !isProcessGoneError(err) {
		return true, err
	}
	return true, nil
}

func isProcessGroupAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(-pid, syscall.Signal(0))
	return err == nil || isProcessPermissionError(err)
}
