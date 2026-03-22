//go:build !linux

package sandbox

import "fmt"

type LandlockRule struct {
	Path     string
	Readable bool
	Writable bool
	Exec     bool
}

func ApplyLandlockRules(_ []LandlockRule) error {
	return fmt.Errorf("landlock: not supported on this platform (Linux 5.13+ required)")
}

func PolicyToLandlockRules(_ *SandboxConfig, _ []string) []LandlockRule {
	return nil
}
