//go:build windows

package daemon

import (
	"os"
	"syscall"
)

func daemonNotifySignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func isReloadSignal(_ os.Signal) bool {
	return false
}

func isChaosDegradedSignal(_ os.Signal) bool {
	return false
}

func isChaosFaultSignal(_ os.Signal) bool {
	return false
}
