// Package sandbox — execution environment isolation.
//
// Defines ToolMeta.ExecutionEnvironment, sandbox configurations for
// Firecracker/gVisor/Docker, and isolation policy conditions for DPR.
package sandbox

import (
	"fmt"
	"sync"
)

// Environment identifies the execution isolation level.
type Environment string

const (
	EnvNone        Environment = "none"        // no isolation
	EnvDocker      Environment = "docker"      // Docker container
	EnvGVisor      Environment = "gvisor"      // gVisor sandbox
	EnvFirecracker Environment = "firecracker" // Firecracker microVM
	EnvWASM        Environment = "wasm"        // WebAssembly sandbox
)

// SandboxConfig defines isolation parameters for tool execution.
type SandboxConfig struct {
	Environment    Environment `json:"environment"`
	Image          string      `json:"image,omitempty"`       // container image
	CPULimit       float64     `json:"cpu_limit,omitempty"`   // CPU cores
	MemoryLimitMB  int         `json:"memory_limit_mb,omitempty"`
	TimeoutSecs    int         `json:"timeout_secs,omitempty"`
	NetworkPolicy  string      `json:"network_policy"`        // "none", "egress_only", "full"
	ReadOnlyRoot   bool        `json:"read_only_root"`
	NoNewPrivileges bool       `json:"no_new_privileges"`
	AllowedSyscalls []string   `json:"allowed_syscalls,omitempty"` // seccomp profile
}

// ToolExecutionMeta describes the execution environment for a tool.
type ToolExecutionMeta struct {
	ToolID      string         `json:"tool_id"`
	Required    Environment    `json:"required_environment"` // minimum isolation
	Config      *SandboxConfig `json:"config,omitempty"`
	BlastRadius string         `json:"blast_radius"` // "none", "local", "network", "global"
}

// IsolationPolicy governs which tools require sandboxing.
type IsolationPolicy struct {
	mu        sync.Mutex
	toolEnvs  map[string]*ToolExecutionMeta // toolID → required environment
	defaults  SandboxConfig
}

// NewIsolationPolicy creates an isolation policy.
func NewIsolationPolicy(defaults SandboxConfig) *IsolationPolicy {
	return &IsolationPolicy{
		toolEnvs: make(map[string]*ToolExecutionMeta),
		defaults: defaults,
	}
}

// RegisterTool declares execution environment requirements for a tool.
func (ip *IsolationPolicy) RegisterTool(meta ToolExecutionMeta) {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	ip.toolEnvs[meta.ToolID] = &meta
}

// RequiredEnvironment returns the minimum isolation for a tool.
func (ip *IsolationPolicy) RequiredEnvironment(toolID string) (Environment, *SandboxConfig) {
	ip.mu.Lock()
	defer ip.mu.Unlock()

	meta, ok := ip.toolEnvs[toolID]
	if !ok {
		return EnvNone, &ip.defaults
	}
	if meta.Config != nil {
		return meta.Required, meta.Config
	}
	return meta.Required, &ip.defaults
}

// CheckIsolation verifies that a tool call meets isolation requirements.
func (ip *IsolationPolicy) CheckIsolation(toolID string, currentEnv Environment) (bool, string) {
	ip.mu.Lock()
	defer ip.mu.Unlock()

	meta, ok := ip.toolEnvs[toolID]
	if !ok {
		return true, "" // no requirement
	}

	if envRank(currentEnv) < envRank(meta.Required) {
		return false, fmt.Sprintf("ISOLATION_REQUIRED: tool %s requires %s isolation (current: %s)",
			toolID, meta.Required, currentEnv)
	}
	return true, ""
}

// BlastRadius returns the blast radius classification for a tool.
func (ip *IsolationPolicy) BlastRadius(toolID string) string {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	meta, ok := ip.toolEnvs[toolID]
	if !ok {
		return "unknown"
	}
	return meta.BlastRadius
}

func envRank(env Environment) int {
	switch env {
	case EnvNone:
		return 0
	case EnvDocker:
		return 1
	case EnvGVisor:
		return 2
	case EnvFirecracker:
		return 3
	case EnvWASM:
		return 1 // same as Docker
	default:
		return 0
	}
}

// DefaultDockerConfig returns a secure Docker sandbox configuration.
func DefaultDockerConfig() SandboxConfig {
	return SandboxConfig{
		Environment:     EnvDocker,
		CPULimit:        1.0,
		MemoryLimitMB:   256,
		TimeoutSecs:     30,
		NetworkPolicy:   "none",
		ReadOnlyRoot:    true,
		NoNewPrivileges: true,
	}
}

// DefaultFirecrackerConfig returns a Firecracker microVM configuration.
func DefaultFirecrackerConfig() SandboxConfig {
	return SandboxConfig{
		Environment:     EnvFirecracker,
		CPULimit:        2.0,
		MemoryLimitMB:   512,
		TimeoutSecs:     60,
		NetworkPolicy:   "egress_only",
		ReadOnlyRoot:    true,
		NoNewPrivileges: true,
	}
}
