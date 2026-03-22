package hub

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultInstallRoot returns ~/.faramesh/hub/packs unless overridden.
func DefaultInstallRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".faramesh", "hub", "packs"), nil
}

// PackInstallDir is the directory for one pack name and version (name may contain /).
func PackInstallDir(root, name, version string) string {
	safe := strings.ReplaceAll(name, string(os.PathSeparator), "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	return filepath.Join(root, safe, "versions", version)
}

// PackPolicyPath returns policy.yaml path under the pack install dir.
func PackPolicyPath(root, name, version string) string {
	return filepath.Join(PackInstallDir(root, name, version), "policy.yaml")
}

// ParsePackRef splits "org/pack" or "org/pack@1.2.0" into name and version (version may be empty).
func ParsePackRef(ref string) (name, version string, err error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", fmt.Errorf("empty pack reference")
	}
	at := strings.LastIndex(ref, "@")
	if at < 0 {
		return ref, "", nil
	}
	if at == 0 || at == len(ref)-1 {
		return "", "", fmt.Errorf("invalid pack reference %q", ref)
	}
	return ref[:at], ref[at+1:], nil
}
