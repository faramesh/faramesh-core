//go:build !linux && !darwin

package sandbox

func applyAgentPlatformFull(_ AgentPlatformConfig) error {
	return nil
}

func platformLayersForOS() PlatformLayers {
	return PlatformLayers{NetworkProxy: true}
}
