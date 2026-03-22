//go:build !linux

package sandbox

import "fmt"

type SeccompProfile struct {
	DefaultAction string         `json:"defaultAction"`
	Syscalls      []SeccompEntry `json:"syscalls"`
}

type SeccompEntry struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

func GenerateSeccompProfile(_ *SandboxConfig) *SeccompProfile {
	return &SeccompProfile{DefaultAction: "SCMP_ACT_ALLOW"}
}

func WriteSeccompProfile(p *SeccompProfile, path string) error {
	return fmt.Errorf("seccomp: not supported on this platform")
}

func InstallSeccompFilter(_ *SandboxConfig) error {
	return fmt.Errorf("seccomp: not supported on this platform (Linux required)")
}
