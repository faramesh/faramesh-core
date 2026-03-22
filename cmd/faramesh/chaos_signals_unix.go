//go:build !windows

package main

import "syscall"

func chaosDegradedSignal() (syscall.Signal, bool) {
	return syscall.SIGUSR1, true
}

func chaosFaultSignal() (syscall.Signal, bool) {
	return syscall.SIGUSR2, true
}
