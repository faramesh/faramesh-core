//go:build !windows

package daemon

import (
	"syscall"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/degraded"
	"go.uber.org/zap"
)

func TestHandleSignalSIGUSR1TogglesDegradedMode(t *testing.T) {
	d := &Daemon{
		log:      zap.NewNop(),
		degraded: degraded.NewManager(),
	}
	if got := d.degraded.Current().String(); got != "FULL" {
		t.Fatalf("expected FULL mode initially, got %s", got)
	}
	if stop := d.handleSignal(syscall.SIGUSR1); stop {
		t.Fatalf("expected daemon to continue on SIGUSR1")
	}
	if got := d.degraded.Current().String(); got != "STATELESS" {
		t.Fatalf("expected STATELESS after SIGUSR1, got %s", got)
	}
}

func TestHandleSignalSIGUSR2TogglesFaultMode(t *testing.T) {
	d := &Daemon{
		log:      zap.NewNop(),
		degraded: degraded.NewManager(),
	}
	if stop := d.handleSignal(syscall.SIGUSR2); stop {
		t.Fatalf("expected daemon to continue on SIGUSR2")
	}
	if got := d.degraded.Current().String(); got != "EMERGENCY" {
		t.Fatalf("expected EMERGENCY after SIGUSR2, got %s", got)
	}
	if stop := d.handleSignal(syscall.SIGUSR2); stop {
		t.Fatalf("expected daemon to continue on SIGUSR2")
	}
	if got := d.degraded.Current().String(); got != "FULL" {
		t.Fatalf("expected FULL after second SIGUSR2, got %s", got)
	}
}
