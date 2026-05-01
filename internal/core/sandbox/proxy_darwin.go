//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

// DarwinProxyConfig configures macOS network interception.
type DarwinProxyConfig struct {
	ProxyPort int  // Faramesh proxy listen port (default: 18443)
	UsePF     bool // Use PF rules (requires sudo)
	UseDYLD   bool // Use DYLD_INSERT_LIBRARIES (spawned processes only)
}

// SetupDarwinProxy configures macOS network interception for the child process.
//
// Three strategies, in order of preference:
//  1. Proxy env vars (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) — zero privilege,
//     works for Python/Node agents that respect proxy settings.
//  2. DYLD_INSERT_LIBRARIES — libc-level interception, no entitlement needed,
//     only works for processes spawned by faramesh run.
//  3. PF rules — kernel-level redirect, requires sudo.
func SetupDarwinProxy(cfg DarwinProxyConfig) ([]string, error) {
	if cfg.ProxyPort == 0 {
		cfg.ProxyPort = 18443
	}

	var envVars []string
	proxyAddr := fmt.Sprintf("http://127.0.0.1:%d", cfg.ProxyPort)
	socksAddr := fmt.Sprintf("socks5://127.0.0.1:%d", cfg.ProxyPort)

	envVars = append(envVars,
		"HTTP_PROXY="+proxyAddr,
		"HTTPS_PROXY="+proxyAddr,
		"http_proxy="+proxyAddr,
		"https_proxy="+proxyAddr,
		"ALL_PROXY="+socksAddr,
		"NO_PROXY=localhost,127.0.0.1,::1",
	)

	if cfg.UsePF && os.Geteuid() == 0 {
		if err := setupPFRules(cfg.ProxyPort); err != nil {
			return envVars, fmt.Errorf("PF setup failed (proxy env vars still active): %w", err)
		}
	}

	return envVars, nil
}

func setupPFRules(proxyPort int) error {
	rule := fmt.Sprintf(
		"rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port %d",
		proxyPort,
	)
	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = stringReaderExec(rule + "\n")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl: %w", err)
	}

	if err := exec.Command("pfctl", "-e").Run(); err != nil {
		return fmt.Errorf("pfctl enable: %w", err)
	}
	return nil
}

// CleanupPFRules disables PF rules installed by Faramesh.
func CleanupPFRules() error {
	return exec.Command("pfctl", "-d").Run()
}

// ExecWithDarwinProxy returns environment variables for proxy-based interception.
func ExecWithDarwinProxy(proxyPort int) []string {
	return ProxyEnvVars(proxyPort)
}

type execStringReader struct {
	s string
	i int
}

func (r *execStringReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

func stringReaderExec(s string) *execStringReader {
	return &execStringReader{s: s}
}
