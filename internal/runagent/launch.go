package runagent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/faramesh/faramesh-core/internal/core/sandbox"
)

// Options configures agent process launch.
type Options struct {
	Profile      string
	Broker       bool
	AgentID      string
	Workspace    string
	ProxyPort    int
	ReportWriter *os.File
}

// Launch starts the agent command with platform enforcement and env wiring.
func Launch(argv []string, opt Options) error {
	if len(argv) == 0 {
		return fmt.Errorf("pass agent command after --")
	}
	profile := opt.Profile
	if profile == "" {
		profile = "auto"
	}

	env := os.Environ()
	var stripped []string
	if opt.Broker {
		env, stripped = StripBrokerSecrets(env)
	}
	env = AugmentAgentEnv(env, opt.AgentID)

	if opt.Workspace == "" {
		opt.Workspace, _ = os.Getwd()
	}

	layers := sandbox.ActivePlatformLayers(profile)
	rep := Report{
		Profile:      profile,
		Broker:       opt.Broker,
		StrippedKeys: stripped,
		Layers:       layers,
		Skipped:      map[string]string{},
	}
	if rw := opt.ReportWriter; rw != nil {
		rep.Write(rw)
	} else {
		rep.Write(os.Stderr)
	}

	var cmd *exec.Cmd
	minimal := profile == "minimal" || profile == "off"

	switch {
	case runtime.GOOS == "linux" && !minimal:
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		childArgs := append([]string{"__sandbox-exec", profile, opt.Workspace, fmt.Sprintf("%d", opt.ProxyPort), "--"}, argv...)
		cmd = exec.Command(exe, childArgs...)
	case runtime.GOOS == "darwin" && !minimal:
		cmd = exec.Command(argv[0], argv[1:]...)
		profilePath, cleanup, err := sandbox.WriteSeatbeltProfile([]string{opt.Workspace}, opt.ProxyPort)
		if err != nil {
			return err
		}
		defer cleanup()
		sandbox.WrapCommandWithSeatbelt(cmd, profilePath)
	default:
		cmd = exec.Command(argv[0], argv[1:]...)
	}

	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// SandboxExecChild applies Linux sandbox in-process then execs argv (hidden CLI).
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
	return syscallExec(bin, argv[1:], os.Environ())
}
