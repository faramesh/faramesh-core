//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

func daemonNotifySignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2}
}

func isReloadSignal(sig os.Signal) bool {
	return sig == syscall.SIGHUP
}

func isChaosDegradedSignal(sig os.Signal) bool {
	return sig == syscall.SIGUSR1
}

func isChaosFaultSignal(sig os.Signal) bool {
	return sig == syscall.SIGUSR2
}
