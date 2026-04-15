// Package ebpf defines the A6 eBPF adapter interface for kernel-level
// syscall interception on Linux 5.8+.
//
// STATUS: SCAFFOLDED — the Probe type, SyscallEvent, and Govern path are
// implemented, but the BPF program loading is not wired. Attach() returns an
// explicit not-implemented error (or configured fallback) instead of claiming
// success. checkCAPBPF() and checkKernelVersion() conservatively return false.
//
// The actual eBPF ELF loader lives in adapter_linux.go (uses cilium/ebpf)
// and handles generic BPF program attachment. The LSM-specific probe
// described below is a future integration target.
//
// Design target (not yet implemented):
//   - Linux 5.8+ kernel with BPF_LSM support
//   - CAP_BPF + CAP_PERFMON capabilities
//   - BTF (BPF Type Format) enabled in the kernel
//   - DEFER via SIGSTOP/SIGCONT
//
// On non-Linux systems or without CAP_BPF, the adapter falls back
// to A3 (HTTP proxy) mode.
package ebpf

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/faramesh/faramesh-core/internal/core"
)

// Probe is the eBPF adapter that attaches BPF programs to LSM hooks
// for syscall-level governance.
type Probe struct {
	pipeline  *core.Pipeline
	config    ProbeConfig
	mu        sync.RWMutex
	attached  bool
	agentPIDs map[int]string // PID → agentID
}

// ProbeConfig holds configuration for the eBPF probe.
type ProbeConfig struct {
	// Pipeline is the governance evaluation pipeline.
	Pipeline *core.Pipeline

	// SyscallHooks specifies which syscalls to intercept.
	// Default: ["execve", "openat", "connect", "sendto"]
	SyscallHooks []string

	// FallbackToProxy enables automatic fallback to A3 if eBPF is unavailable.
	FallbackToProxy bool

	// A3ProxyAddr is the A3 proxy address to fall back to.
	A3ProxyAddr string
}

// ProbeStatus reports the probe's runtime state.
type ProbeStatus struct {
	Available      bool     `json:"available"`
	Attached       bool     `json:"attached"`
	Platform       string   `json:"platform"`
	KernelVersion  string   `json:"kernel_version"`
	Hooks          []string `json:"hooks"`
	FallbackActive bool     `json:"fallback_active"`
	FallbackTarget string   `json:"fallback_target,omitempty"`
}

// NewProbe creates a new eBPF probe.
func NewProbe(cfg ProbeConfig) *Probe {
	if len(cfg.SyscallHooks) == 0 {
		cfg.SyscallHooks = []string{"execve", "openat", "connect", "sendto"}
	}
	return &Probe{
		pipeline:  cfg.Pipeline,
		config:    cfg,
		agentPIDs: make(map[int]string),
	}
}

// Available checks whether eBPF is supported on this system.
func (p *Probe) Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Check for CAP_BPF capability.
	if !checkCAPBPF() {
		return false
	}
	// Check kernel version >= 5.8.
	if !checkKernelVersion() {
		return false
	}
	return true
}

// Attach loads the BPF programs and attaches them to LSM hooks.
// Until the real LSM loader is implemented, this returns an explicit
// not-implemented error (or configured fallback) rather than reporting success.
func (p *Probe) Attach() error {
	if runtime.GOOS != "linux" {
		if p.config.FallbackToProxy {
			return &FallbackError{
				Reason:  "eBPF not available on " + runtime.GOOS,
				Target:  "a3_proxy",
				Address: p.config.A3ProxyAddr,
			}
		}
		return fmt.Errorf("eBPF adapter requires Linux 5.8+ (current: %s)", runtime.GOOS)
	}

	if !checkCAPBPF() {
		if p.config.FallbackToProxy {
			return &FallbackError{
				Reason:  "CAP_BPF not available",
				Target:  "a3_proxy",
				Address: p.config.A3ProxyAddr,
			}
		}
		return fmt.Errorf("eBPF adapter requires CAP_BPF capability")
	}
	if !checkKernelVersion() {
		if p.config.FallbackToProxy {
			return &FallbackError{
				Reason:  "Linux kernel 5.8+ with BPF LSM support not detected",
				Target:  "a3_proxy",
				Address: p.config.A3ProxyAddr,
			}
		}
		return fmt.Errorf("eBPF adapter requires Linux kernel 5.8+ with BPF LSM support")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.attached = false
	if p.config.FallbackToProxy {
		return &FallbackError{
			Reason:  "eBPF LSM loader is scaffolded but not implemented in this build",
			Target:  "a3_proxy",
			Address: p.config.A3ProxyAddr,
		}
	}
	return fmt.Errorf("eBPF LSM loader is scaffolded but not implemented in this build")
}

// Detach removes BPF programs from LSM hooks.
func (p *Probe) Detach() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attached = false
	return nil
}

// RegisterAgent associates a PID with an agent ID for governance decisions.
func (p *Probe) RegisterAgent(pid int, agentID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.agentPIDs[pid] = agentID
}

// UnregisterAgent removes a PID→agentID mapping.
func (p *Probe) UnregisterAgent(pid int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.agentPIDs, pid)
}

// Status returns the probe's current status.
func (p *Probe) Status() ProbeStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return ProbeStatus{
		Available:      p.Available(),
		Attached:       p.attached,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		Hooks:          p.config.SyscallHooks,
		FallbackActive: !p.attached && p.config.FallbackToProxy,
		FallbackTarget: p.config.A3ProxyAddr,
	}
}

// Govern is the userspace evaluation path called from the BPF ring buffer
// callback. In production, the BPF program sends syscall events to a ring
// buffer, and this function evaluates them through the pipeline.
func (p *Probe) Govern(ctx context.Context, event SyscallEvent) core.Decision {
	p.mu.RLock()
	agentID := p.agentPIDs[event.PID]
	p.mu.RUnlock()

	if agentID == "" {
		agentID = fmt.Sprintf("pid:%d", event.PID)
	}

	car := core.CanonicalActionRequest{
		CallID:           fmt.Sprintf("ebpf-%d-%d", event.PID, event.Timestamp),
		AgentID:          agentID,
		ToolID:           event.ToolID(),
		Args:             event.Args(),
		InterceptAdapter: "ebpf",
	}

	return p.pipeline.Evaluate(car)
}

// SyscallEvent represents a syscall intercepted by the BPF program.
type SyscallEvent struct {
	PID       int    `json:"pid"`
	Syscall   string `json:"syscall"` // "execve", "openat", "connect", "sendto"
	Path      string `json:"path"`    // for openat/execve
	Addr      string `json:"addr"`    // for connect/sendto
	Port      int    `json:"port"`    // for connect/sendto
	Comm      string `json:"comm"`    // process command name
	Timestamp int64  `json:"timestamp"`
}

// ToolID derives a Faramesh tool ID from the syscall event.
func (e SyscallEvent) ToolID() string {
	switch e.Syscall {
	case "execve":
		return "shell/exec"
	case "openat":
		return "fs/open"
	case "connect":
		return fmt.Sprintf("net/connect:%d", e.Port)
	case "sendto":
		return "net/send"
	default:
		return "syscall/" + e.Syscall
	}
}

// Args converts the syscall event fields to a tool args map.
func (e SyscallEvent) Args() map[string]any {
	args := map[string]any{
		"syscall": e.Syscall,
		"comm":    e.Comm,
	}
	if e.Path != "" {
		args["path"] = e.Path
	}
	if e.Addr != "" {
		args["addr"] = e.Addr
	}
	if e.Port > 0 {
		args["port"] = e.Port
	}
	return args
}

// FallbackError indicates eBPF is unavailable and suggests fallback to A3.
type FallbackError struct {
	Reason  string
	Target  string // "a3_proxy"
	Address string
}

func (e *FallbackError) Error() string {
	return fmt.Sprintf("eBPF fallback to %s at %s: %s", e.Target, e.Address, e.Reason)
}

// checkCAPBPF checks if the current process has CAP_BPF.
func checkCAPBPF() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Check /proc/self/status for CapEff containing CAP_BPF (bit 39).
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	_ = data     // Full capability check would parse CapEff line.
	return false // Conservative: return false until BPF lib integrated.
}

// checkKernelVersion checks if the kernel version is >= 5.8.
func checkKernelVersion() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// Would parse /proc/version or use uname syscall.
	return false // Conservative default.
}
