package runagent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/faramesh/faramesh-core/internal/core/sandbox"
)

// SandboxExecChild applies OS sandbox in-process then execs argv (hidden __agent-exec / generated launcher).
func SandboxExecChild(profile, workspace, proxyPortStr string, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty argv")
	}
	port := 0
	_, _ = fmt.Sscanf(proxyPortStr, "%d", &port)
	cfg := sandbox.AgentPlatformConfig{
		SandboxConfig:  sandbox.DefaultDockerConfig(),
		WorkspacePaths: []string{workspace},
		Profile:        profile,
		ProxyPort:      port,
	}
	if profile != "minimal" && profile != "off" {
		if err := sandbox.ApplyAgentPlatformEnforcement(cfg); err != nil {
			return err
		}
	}
	bin := argv[0]
	if !filepath.IsAbs(bin) {
		if p, err := exec.LookPath(bin); err == nil {
			bin = p
		}
	}
	env := os.Environ()
	if os.Getenv("FARAMESH_STRIP_AMBIENT") == "1" {
		env, _ = StripBrokerSecrets(env)
	}
	return syscallExec(bin, argv[1:], env)
}
