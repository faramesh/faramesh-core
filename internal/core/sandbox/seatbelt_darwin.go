//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WriteSeatbeltProfile emits a Seatbelt (sandbox-exec) policy for agent containment.
// Denies signaling foreign processes, limits filesystem writes to workspace + tmp,
// and steers network through the local Faramesh proxy when configured.
func WriteSeatbeltProfile(workspacePaths []string, proxyPort int) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "faramesh-seatbelt-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, "agent.sb")

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow process-exec)\n")
	b.WriteString("(allow file-read-metadata)\n")
	b.WriteString("(allow file-read-data)\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow mach-lookup)\n")
	b.WriteString("(allow ipc-posix-shm*)\n")
	b.WriteString("(allow signal (target self))\n")
	b.WriteString("(deny signal)\n")

	for _, wp := range workspacePaths {
		wp = strings.TrimSpace(wp)
		if wp == "" {
			continue
		}
		abs, _ := filepath.Abs(wp)
		fmt.Fprintf(&b, "(allow file-read* (subpath %q))\n", abs)
		fmt.Fprintf(&b, "(allow file-write* (subpath %q))\n", abs)
	}
	b.WriteString("(allow file-write* (subpath \"/tmp\"))\n")
	b.WriteString("(allow file-write* (subpath \"/private/tmp\"))\n")
	b.WriteString("(allow file-write* (subpath \"/var/folders\"))\n")

	if proxyPort > 0 {
		fmt.Fprintf(&b, "(allow network-outbound (remote tcp \"localhost:%d\"))\n", proxyPort)
		b.WriteString("(deny network-outbound)\n")
	} else {
		b.WriteString("(allow network-outbound)\n")
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func applyAgentPlatformFull(cfg AgentPlatformConfig) error {
	profilePath, cleanup, err := WriteSeatbeltProfile(cfg.WorkspacePaths, cfg.ProxyPort)
	if err != nil {
		return err
	}
	_ = profilePath
	_ = cleanup
	// Seatbelt applies at exec via WrapCommandWithSeatbelt; load-once marker for report.
	return nil
}

func platformLayersForOS() PlatformLayers {
	return PlatformLayers{Seatbelt: true, NetworkProxy: true}
}

// WrapCommandWithSeatbelt rewrites cmd to run under sandbox-exec with the profile at profilePath.
func WrapCommandWithSeatbelt(cmd *exec.Cmd, profilePath string) {
	if profilePath == "" {
		return
	}
	inner := append([]string{cmd.Path}, cmd.Args[1:]...)
	cmd.Path, _ = exec.LookPath("sandbox-exec")
	cmd.Args = append([]string{"sandbox-exec", "-f", profilePath}, inner...)
}
