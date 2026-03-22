//go:build linux

package sandbox

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// NetNSConfig configures network namespace isolation for an agent process.
type NetNSConfig struct {
	Name          string // namespace name (e.g. "faramesh-agent-1234")
	ProxyPort     int    // local port the Faramesh proxy listens on
	RedirectPorts []int  // destination ports to redirect (e.g. 80, 443)
	AllowedCIDRs  []string // CIDRs exempt from redirect (e.g. daemon socket)
}

// SetupNetworkNamespace creates an isolated network namespace, sets up a veth
// pair for connectivity, and installs iptables REDIRECT rules so all outbound
// traffic from the agent process passes through the Faramesh proxy.
func SetupNetworkNamespace(cfg NetNSConfig) error {
	ns := cfg.Name
	if ns == "" {
		return fmt.Errorf("netns: name required")
	}

	cmds := [][]string{
		{"ip", "netns", "add", ns},
		{"ip", "link", "add", "veth-" + ns, "type", "veth", "peer", "name", "vpeer-" + ns},
		{"ip", "link", "set", "vpeer-" + ns, "netns", ns},
		{"ip", "addr", "add", "10.200.1.1/30", "dev", "veth-" + ns},
		{"ip", "link", "set", "veth-" + ns, "up"},
		{"ip", "netns", "exec", ns, "ip", "addr", "add", "10.200.1.2/30", "dev", "vpeer-" + ns},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "vpeer-" + ns, "up"},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", "10.200.1.1"},
	}

	for _, args := range cmds {
		if err := run(args); err != nil {
			return fmt.Errorf("netns setup %q: %w", strings.Join(args, " "), err)
		}
	}

	// NAT outbound from namespace.
	if err := run([]string{
		"iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", "10.200.1.2/30", "-j", "MASQUERADE",
	}); err != nil {
		return fmt.Errorf("netns NAT: %w", err)
	}

	// Redirect target ports inside namespace to the Faramesh proxy.
	proxyPort := strconv.Itoa(cfg.ProxyPort)
	ports := cfg.RedirectPorts
	if len(ports) == 0 {
		ports = []int{80, 443, 8080, 8443}
	}
	for _, port := range ports {
		if err := run([]string{
			"ip", "netns", "exec", ns,
			"iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp", "--dport", strconv.Itoa(port),
			"-j", "REDIRECT", "--to-port", proxyPort,
		}); err != nil {
			return fmt.Errorf("netns redirect port %d: %w", port, err)
		}
	}

	return nil
}

// CleanupNetworkNamespace removes the namespace and its veth pair.
func CleanupNetworkNamespace(name string) error {
	_ = run([]string{"ip", "link", "del", "veth-" + name})
	return run([]string{"ip", "netns", "del", name})
}

// ExecInNamespace runs a command inside the given network namespace.
// Returns the argv for use with syscall.Exec.
func ExecInNamespace(ns string, argv []string) []string {
	return append([]string{"ip", "netns", "exec", ns}, argv...)
}

func run(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
