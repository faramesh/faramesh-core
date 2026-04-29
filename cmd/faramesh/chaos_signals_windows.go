//go:build windows

package main

import "syscall"

func chaosDegradedSignal() (syscall.Signal, bool) {
	return 0, false
}

func chaosFaultSignal() (syscall.Signal, bool) {
	return 0, false
}
