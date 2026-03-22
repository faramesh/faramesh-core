//go:build windows

package sandbox

import (
	"fmt"
	"strconv"
)

// WindowsProxyConfig configures Windows network interception.
type WindowsProxyConfig struct {
	ProxyPort    int  // Faramesh proxy listen port
	UseWinDivert bool // Use WinDivert for kernel-level interception (requires admin)
}

// SetupWindowsProxy configures Windows network interception.
//
// Two strategies:
//   1. Proxy env vars — zero privilege, works for agents that respect proxy settings.
//   2. WinDivert — kernel-level, pre-signed driver, requires admin only.
//      Ships as bundled WinDivert.dll + WinDivert64.sys (pre-signed by WinDivert project).
func SetupWindowsProxy(cfg WindowsProxyConfig) ([]string, error) {
	if cfg.ProxyPort == 0 {
		cfg.ProxyPort = 18443
	}

	proxyAddr := fmt.Sprintf("http://127.0.0.1:%d", cfg.ProxyPort)
	socksAddr := fmt.Sprintf("socks5://127.0.0.1:%d", cfg.ProxyPort)

	envVars := []string{
		"HTTP_PROXY=" + proxyAddr,
		"HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr,
		"https_proxy=" + proxyAddr,
		"ALL_PROXY=" + socksAddr,
		"NO_PROXY=localhost,127.0.0.1,::1",
	}

	if cfg.UseWinDivert {
		if err := setupWinDivert(cfg.ProxyPort); err != nil {
			return envVars, fmt.Errorf("WinDivert setup failed (proxy env vars still active): %w", err)
		}
	}

	return envVars, nil
}

func setupWinDivert(proxyPort int) error {
	// WinDivert integration requires the pre-signed driver binaries:
	//   WinDivert.dll, WinDivert64.sys
	// bundled in the Faramesh release distribution.
	//
	// Uses github.com/williamfzc/go-windivert Go bindings:
	//   handle, err := windivert.Open(
	//       fmt.Sprintf("tcp.DstPort == 443", agentPID),
	//       windivert.LayerNetwork, 0, windivert.FlagDefault,
	//   )
	//
	// For now: return nil to indicate WinDivert is not yet wired.
	// The proxy env var approach provides functional interception.
	return fmt.Errorf("WinDivert kernel interception not yet wired (use proxy env vars)")
}

// ExecWithWindowsProxy returns environment variables for proxy-based interception.
func ExecWithWindowsProxy(proxyPort int) []string {
	addr := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	return []string{
		"HTTP_PROXY=" + addr,
		"HTTPS_PROXY=" + addr,
		"http_proxy=" + addr,
		"https_proxy=" + addr,
		"ALL_PROXY=socks5://127.0.0.1:" + strconv.Itoa(proxyPort),
		"NO_PROXY=localhost,127.0.0.1,::1",
	}
}
