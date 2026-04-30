//go:build windows

package main

import "os/exec"

func applyProcessGroup(cmd *exec.Cmd) {
	// Windows does not support Setpgid on SysProcAttr.
}

func terminateProcessGroup(pid int) (bool, error) {
	return false, nil
}

func isProcessGroupAlive(pid int) bool {
	return false
}
