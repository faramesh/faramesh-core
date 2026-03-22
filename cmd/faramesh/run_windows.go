//go:build windows

package main

import (
	"os"
	"os/exec"
)

func syscallExec(name string, argv []string, env []string) error {
	cmd := exec.Command(name, argv[1:]...)
	cmd.Path = name
	cmd.Args = argv
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
