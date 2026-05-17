package dpr

import (
	"os"
	"strings"

	sd_daemon "github.com/coreos/go-systemd/v22/daemon"
)

// NotifyWatchdog sends sd_notify WATCHDOG=1 when running under systemd (INVOCATION_ID set).
func NotifyWatchdog() {
	if strings.TrimSpace(os.Getenv("INVOCATION_ID")) == "" {
		return
	}
	_, _ = sd_daemon.SdNotify(false, "WATCHDOG=1\n")
}
