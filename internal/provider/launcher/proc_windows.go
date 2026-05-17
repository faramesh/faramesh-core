//go:build windows

package launcher

import "os/exec"

func configureProcessGroup(cmd *exec.Cmd) {}

func terminateSidecar(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
