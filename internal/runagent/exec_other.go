//go:build !unix

package runagent

import (
	"os/exec"
)

func syscallExec(bin string, args []string, env []string) error {
	return exec.Command(bin, args...).Run()
}
