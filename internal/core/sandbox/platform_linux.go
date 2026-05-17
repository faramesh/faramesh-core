//go:build linux

package sandbox

func applyAgentPlatformFull(cfg AgentPlatformConfig) error {
	if err := InstallSeccompFilter(&cfg.SandboxConfig); err != nil {
		return err
	}
	rules := PolicyToLandlockRules(&cfg.SandboxConfig, cfg.WorkspacePaths)
	return ApplyLandlockRules(rules)
}

func platformLayersForOS() PlatformLayers {
	return PlatformLayers{Seccomp: true, Landlock: true, NetworkProxy: true}
}
