package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const publicInstallerURL = "https://install.faramesh.dev/install.sh"

var updateVersion string

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update Faramesh to the latest release",
	RunE:  runUpdate,
}

var uninstallBinaryOnly bool
var uninstallPurge bool
var uninstallYes bool

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the Faramesh binary or purge local artifacts",
	RunE:  runUninstall,
}

func init() {
	updateCmd.Flags().StringVar(&updateVersion, "version", "latest", "release version to install")

	uninstallCmd.Flags().BoolVar(&uninstallBinaryOnly, "binary-only", false, "remove installed binaries only")
	uninstallCmd.Flags().BoolVar(&uninstallPurge, "purge", false, "remove binaries and local Faramesh artifacts")
	uninstallCmd.Flags().BoolVar(&uninstallYes, "yes", false, "skip confirmation prompts")
	uninstallCmd.Flags().StringVar(&stackDirFlag, "dir", "", "stack directory to purge when using --purge")
}

func runUpdate(_ *cobra.Command, _ []string) error {
	if updateVersion != "" && updateVersion != "latest" {
		cmd := exec.Command("bash", "-lc", fmt.Sprintf("curl -fsSL %s | bash -s -- --update --no-interactive --version %s", shellQuote(publicInstallerURL), shellQuote(updateVersion)))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		return cmd.Run()
	}

	cmd := exec.Command("bash", "-lc", fmt.Sprintf("curl -fsSL %s | bash -s -- --update --no-interactive", shellQuote(publicInstallerURL)))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func runUninstall(_ *cobra.Command, _ []string) error {
	if uninstallBinaryOnly && uninstallPurge {
		return fmt.Errorf("choose either --binary-only or --purge, not both")
	}
	if !uninstallBinaryOnly && !uninstallPurge {
		uninstallBinaryOnly = true
	}

	mode := "binary-only"
	if uninstallPurge {
		mode = "purge"
	}

	if !uninstallYes {
		fmt.Printf("This will remove Faramesh in %s mode. Continue? [y/N]: ", mode)
		var answer string
		if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
			return err
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("aborted")
			return nil
		}
	}

	removed := 0
	for _, candidate := range discoverFarameshBinaries() {
		if err := os.Remove(candidate); err == nil {
			fmt.Printf("removed: %s\n", candidate)
			removed++
		}
	}

	if uninstallPurge {
		stackDir, err := resolveStackDir()
		if err != nil {
			return err
		}
		purgePaths := []string{
			filepath.Join(stackDir, ".faramesh"),
			filepath.Join(stackDir, ".faramesh-wal"),
			filepath.Join(stackDir, ".faramesh-data"),
			filepath.Join(userHomeDir(), ".faramesh"),
		}
		for _, purgePath := range purgePaths {
			if err := os.RemoveAll(purgePath); err == nil {
				fmt.Printf("purged: %s\n", purgePath)
			}
		}
	}

	if removed == 0 {
		fmt.Println("no Faramesh binaries found to remove")
	}

	return nil
}

func discoverFarameshBinaries() []string {
	seen := map[string]struct{}{}
	add := func(path string) {
		if path == "" {
			return
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
	}

	if exe, err := os.Executable(); err == nil {
		add(exe)
	}
	if path, err := exec.LookPath("faramesh"); err == nil {
		add(path)
	}

	dirs := []string{
		filepath.Join(userHomeDir(), ".local", "bin"),
		filepath.Join(userHomeDir(), "go", "bin"),
		filepath.Join(userHomeDir(), ".cargo", "bin"),
		"/usr/local/bin",
		"/opt/homebrew/bin",
	}

	if prefix := commandOutput("npm", "config", "get", "prefix"); prefix != "" {
		dirs = append(dirs, filepath.Join(prefix, "bin"))
	}
	if prefix := commandOutput("brew", "--prefix"); prefix != "" {
		dirs = append(dirs, filepath.Join(prefix, "bin"))
	}
	if gobin := commandOutput("go", "env", "GOBIN"); gobin != "" {
		dirs = append(dirs, gobin)
	} else if gopath := commandOutput("go", "env", "GOPATH"); gopath != "" {
		dirs = append(dirs, filepath.Join(gopath, "bin"))
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		add(filepath.Join(dir, "faramesh"))
		if runtime.GOOS == "windows" {
			add(filepath.Join(dir, "faramesh.exe"))
		}
	}

	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	return paths
}

func commandOutput(name string, args ...string) string {
	if _, err := exec.LookPath(name); err != nil {
		return ""
	}
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func userHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}