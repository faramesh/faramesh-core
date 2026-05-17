//go:build unix

package runagent

import "syscall"

func syscallExec(bin string, args []string, env []string) error {
	argv := append([]string{bin}, args...)
	return syscall.Exec(bin, argv, env)
}
