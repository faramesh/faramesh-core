package sandbox

// AgentPlatformConfig configures OS-level containment for an agent child process.
type AgentPlatformConfig struct {
	SandboxConfig
	WorkspacePaths []string
	Profile        string // auto, full, minimal, off
	ProxyPort      int
}

// ApplyAgentPlatformEnforcement installs syscall/filesystem sandboxing in the
// current process. Call immediately before exec of the agent binary.
func ApplyAgentPlatformEnforcement(cfg AgentPlatformConfig) error {
	switch cfg.Profile {
	case "", "auto", "full":
		return applyAgentPlatformFull(cfg)
	case "minimal", "off":
		return nil
	default:
		return applyAgentPlatformFull(cfg)
	}
}

// PlatformLayers describes which enforcement layers are active on this OS.
type PlatformLayers struct {
	Seccomp      bool
	Landlock     bool
	Seatbelt     bool
	NetworkProxy bool
}

// ActivePlatformLayers returns the layers available on the running OS.
func ActivePlatformLayers(profile string) PlatformLayers {
	if profile == "minimal" || profile == "off" {
		return PlatformLayers{}
	}
	return platformLayersForOS()
}
