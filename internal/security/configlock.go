package security

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// LockConfigFile marks the governance source read-only after apply when immutable_config is set.
func LockConfigFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("chattr", "+i", path)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("chattr +i %s: %w (%s)", path, err, strings.TrimSpace(string(out)))
		}
		return nil
	case "darwin":
		cmd := exec.Command("chflags", "uchg", path)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("chflags uchg %s: %w (%s)", path, err, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return nil
	}
}

// UnlockConfigFile reverses LockConfigFile (used before re-apply).
func UnlockConfigFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("chattr", "-i", path)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("chattr -i %s: %w (%s)", path, err, strings.TrimSpace(string(out)))
		}
		return nil
	case "darwin":
		cmd := exec.Command("chflags", "nouchg", path)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("chflags nouchg %s: %w (%s)", path, err, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return nil
	}
}
