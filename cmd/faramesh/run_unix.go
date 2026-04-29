//go:build !windows

package main

import "syscall"

func syscallExec(name string, argv []string, env []string) error {
	return syscall.Exec(name, argv, env)
}
