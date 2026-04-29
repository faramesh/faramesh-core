//go:build !linux

package sandbox

import "fmt"

type NetNSConfig struct {
	Name          string
	ProxyPort     int
	RedirectPorts []int
	AllowedCIDRs  []string
}

func SetupNetworkNamespace(_ NetNSConfig) error {
	return fmt.Errorf("network namespace isolation requires Linux")
}

func CleanupNetworkNamespace(_ string) error {
	return fmt.Errorf("network namespace cleanup requires Linux")
}

func ExecInNamespace(_ string, argv []string) []string {
	return argv
}
