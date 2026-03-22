//go:build windows

package main

import (
	"fmt"
	"syscall"
)

func sendChaosSignal(_ int, _ syscall.Signal) error {
	return fmt.Errorf("chaos signal toggles are not supported on this platform")
}
