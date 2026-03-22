package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFindDaemonPID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "faramesh.pid"), []byte("4242\n"), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	pid, err := findDaemonPID(dir)
	if err != nil {
		t.Fatalf("find pid: %v", err)
	}
	if pid != 4242 {
		t.Fatalf("expected pid 4242, got %d", pid)
	}
}

func TestDispatchChaosActionToggle(t *testing.T) {
	orig := chaosSendSignal
	t.Cleanup(func() { chaosSendSignal = orig })

	calls := 0
	chaosSendSignal = func(pid int, sig syscall.Signal) error {
		calls++
		if pid != 99 || sig != syscall.SIGUSR1 {
			t.Fatalf("unexpected signal call pid=%d sig=%v", pid, sig)
		}
		return nil
	}

	if err := dispatchChaosAction(99, "toggle", syscall.SIGUSR1); err != nil {
		t.Fatalf("dispatch toggle: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 signal call, got %d", calls)
	}
}

func TestDispatchChaosActionOnSendsTwice(t *testing.T) {
	orig := chaosSendSignal
	t.Cleanup(func() { chaosSendSignal = orig })

	calls := 0
	chaosSendSignal = func(_ int, _ syscall.Signal) error {
		calls++
		return nil
	}
	if err := dispatchChaosAction(10, "on", syscall.SIGUSR2); err != nil {
		t.Fatalf("dispatch on: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 signal calls for on, got %d", calls)
	}
}

func TestDispatchChaosActionRejectsUnknown(t *testing.T) {
	if err := dispatchChaosAction(10, "weird", syscall.SIGUSR2); err == nil {
		t.Fatalf("expected unsupported action error")
	}
}
