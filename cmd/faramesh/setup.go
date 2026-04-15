package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const (
	setupRepo = "faramesh/faramesh-core"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Lifecycle setup and maintenance commands",
}

var setupFlowCmd = &cobra.Command{
	Use:   "flow",
	Short: "Run guided setup flow with native faramesh commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectDir, _ := cmd.Flags().GetString("project-dir")
		dataDir, _ := cmd.Flags().GetString("data-dir")
		policyOut, _ := cmd.Flags().GetString("policy-out")
		agentCmd, _ := cmd.Flags().GetString("agent-cmd")
		cloudPairMode, _ := cmd.Flags().GetString("cloud-pair")
		runNowMode, _ := cmd.Flags().GetString("run-now")
		yes, _ := cmd.Flags().GetBool("yes")

		if dataDir == "" {
			dataDir = filepath.Join(projectDir, ".faramesh")
		}
		if policyOut == "" {
			policyOut = filepath.Join(projectDir, "suggested-policy.yaml")
		}

		cloudPair, err := resolveMode(cloudPairMode, yes, "Pair with Faramesh Cloud now?")
		if err != nil {
			return err
		}
		runNow, err := resolveMode(runNowMode, yes, "Run your agent through governance now?")
		if err != nil {
			return err
		}

		fmt.Println("==> Discovering tools in project")
		if err := runFaramesh("discover", "--cwd", projectDir); err != nil {
			return err
		}

		fmt.Println("==> Attaching Faramesh (shadow mode)")
		if err := runFaramesh("attach", "--cwd", projectDir, "--interactive=false", "--data-dir", dataDir); err != nil {
			return err
		}

		fmt.Println("==> Computing coverage")
		if err := runFaramesh("coverage", "--cwd", projectDir, "--data-dir", dataDir); err != nil {
			return err
		}

		fmt.Println("==> Generating starter policy")
		if err := runFaramesh("suggest", "--data-dir", dataDir, "--out", policyOut); err != nil {
			return err
		}

		fmt.Println("==> Reporting policy gaps")
		if err := runFaramesh("gaps", "--cwd", projectDir, "--data-dir", dataDir, "--policy", policyOut); err != nil {
			return err
		}

		if cloudPair {
			fmt.Println("==> Opening cloud pairing flow")
			if err := runFaramesh("auth", "login"); err != nil {
				return err
			}
		}

		if runNow {
			if strings.TrimSpace(agentCmd) == "" {
				if yes {
					fmt.Println("Skipping run step: --yes was set but --agent-cmd is empty")
					return nil
				}
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Enter agent command to run (for example: python agent.py): ")
				input, readErr := reader.ReadString('\n')
				if readErr != nil && readErr != io.EOF {
					return readErr
				}
				agentCmd = strings.TrimSpace(input)
			}
			if strings.TrimSpace(agentCmd) != "" {
				fmt.Println("==> Running agent through governance")
				if err := runFaramesh("run", "--policy", policyOut, "--", "bash", "-lc", agentCmd); err != nil {
					return err
				}
			}
		}

		fmt.Println("Setup flow complete.")
		return nil
	},
}

var setupUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Detach from projects and remove local Faramesh state",
	RunE: func(cmd *cobra.Command, args []string) error {
		paths, _ := cmd.Flags().GetStringArray("path")
		backupExt, _ := cmd.Flags().GetString("backup-ext")
		removeGenerated, _ := cmd.Flags().GetBool("remove-generated")
		skipOffboard, _ := cmd.Flags().GetBool("skip-offboard")
		yes, _ := cmd.Flags().GetBool("yes")

		if !yes {
			ok, err := askYesNo("This will remove local state under ~/.faramesh and stop local services. Continue?", false)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Println("Cancelled.")
				return nil
			}
		}

		if !skipOffboard {
			for _, p := range paths {
				if strings.TrimSpace(p) == "" {
					continue
				}
				args := []string{"offboard", "--path", p, "--apply", "--backup-ext", backupExt}
				if removeGenerated {
					args = append(args, "--remove-generated")
				}
				if err := runFaramesh(args...); err != nil {
					return err
				}
			}
		}

		_ = runFaramesh("stop")

		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		stateDir := filepath.Join(home, ".faramesh")
		if rmErr := os.RemoveAll(stateDir); rmErr != nil {
			return rmErr
		}

		fmt.Println("Removed local state:", stateDir)
		fmt.Println("Uninstall complete.")
		return nil
	},
}

var setupUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update faramesh binary from GitHub releases",
	RunE: func(cmd *cobra.Command, args []string) error {
		version, _ := cmd.Flags().GetString("version")
		if version == "" {
			version = "latest"
		}
		return performSelfUpdate(version)
	},
}

var setupUpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Alias for setup update",
	RunE: func(cmd *cobra.Command, args []string) error {
		version, _ := cmd.Flags().GetString("version")
		if version == "" {
			version = "latest"
		}
		return performSelfUpdate(version)
	},
}

func init() {
	setupFlowCmd.Flags().String("project-dir", ".", "Project directory")
	setupFlowCmd.Flags().String("data-dir", "", "Observation data directory (default: <project-dir>/.faramesh)")
	setupFlowCmd.Flags().String("policy-out", "", "Suggested policy output path (default: <project-dir>/suggested-policy.yaml)")
	setupFlowCmd.Flags().String("agent-cmd", "", "Agent launch command for the final run step")
	setupFlowCmd.Flags().String("cloud-pair", "auto", "Whether to pair with cloud: auto|yes|no")
	setupFlowCmd.Flags().String("run-now", "auto", "Whether to run the agent after setup: auto|yes|no")
	setupFlowCmd.Flags().Bool("yes", false, "Non-interactive mode; accepts defaults and skips prompts")

	setupUninstallCmd.Flags().StringArray("path", nil, "Project path to offboard before removing local state (repeatable)")
	setupUninstallCmd.Flags().String("backup-ext", ".faramesh.bak", "Backup extension used by offboard")
	setupUninstallCmd.Flags().Bool("remove-generated", true, "Remove generated wrappers/config while offboarding")
	setupUninstallCmd.Flags().Bool("skip-offboard", false, "Skip offboard step and only remove local state")
	setupUninstallCmd.Flags().Bool("yes", false, "Skip confirmation prompt")

	setupUpdateCmd.Flags().String("version", "latest", "Version to install (default: latest)")
	setupUpgradeCmd.Flags().String("version", "latest", "Version to install (default: latest)")

	setupCmd.AddCommand(setupFlowCmd)
	setupCmd.AddCommand(setupUninstallCmd)
	setupCmd.AddCommand(setupUpdateCmd)
	setupCmd.AddCommand(setupUpgradeCmd)
}

func runFaramesh(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func resolveMode(value string, assumeYes bool, prompt string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "y", "true", "1":
		return true, nil
	case "no", "n", "false", "0":
		return false, nil
	case "auto", "":
		if assumeYes {
			return false, nil
		}
		return askYesNo(prompt, false)
	default:
		return false, fmt.Errorf("invalid mode %q (expected auto|yes|no)", value)
	}
}

func askYesNo(prompt string, defaultYes bool) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	if defaultYes {
		fmt.Printf("%s [Y/n]: ", prompt)
	} else {
		fmt.Printf("%s [y/N]: ", prompt)
	}
	input, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultYes, nil
	}
	return input == "y" || input == "yes", nil
}

func performSelfUpdate(version string) error {
	if version == "latest" {
		latest, err := fetchLatestVersion()
		if err != nil {
			return err
		}
		version = latest
	}

	osName := runtime.GOOS
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "amd64"
	} else if arch == "arm64" {
		arch = "arm64"
	} else {
		return fmt.Errorf("unsupported architecture for update: %s", runtime.GOARCH)
	}
	if osName != "darwin" && osName != "linux" && osName != "windows" {
		return fmt.Errorf("unsupported operating system for update: %s", osName)
	}

	asset := fmt.Sprintf("faramesh-%s-%s", osName, arch)
	if osName == "windows" {
		asset += ".exe"
	}

	base := fmt.Sprintf("https://github.com/%s/releases/download/v%s/", setupRepo, version)
	binaryURL := base + asset
	checksumURL := base + asset + ".sha256"

	tmpDir, err := os.MkdirTemp("", "faramesh-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	binaryPath := filepath.Join(tmpDir, asset)
	checksumPath := binaryPath + ".sha256"

	if err := downloadFile(binaryURL, binaryPath); err != nil {
		return err
	}
	if err := downloadFile(checksumURL, checksumPath); err != nil {
		return err
	}

	expected, err := readExpectedChecksum(checksumPath)
	if err != nil {
		return err
	}
	actual, err := hashFile(binaryPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(expected, actual) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	backupPath := exePath + ".bak"

	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return err
	}

	_ = os.Remove(backupPath)
	if err := os.Rename(exePath, backupPath); err != nil {
		return fmt.Errorf("cannot replace %s (need write permission): %w", exePath, err)
	}
	if err := os.Rename(binaryPath, exePath); err != nil {
		_ = os.Rename(backupPath, exePath)
		return fmt.Errorf("update failed while replacing binary: %w", err)
	}
	_ = os.Remove(backupPath)

	fmt.Printf("Updated faramesh to v%s\n", version)
	return nil
}

func fetchLatestVersion() (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", setupRepo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("failed to resolve latest release: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	tag := strings.TrimPrefix(strings.TrimSpace(payload.TagName), "v")
	if tag == "" {
		return "", fmt.Errorf("latest release tag was empty")
	}
	return tag, nil
}

func downloadFile(url string, outPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("download failed from %s: %s %s", url, resp.Status, strings.TrimSpace(string(body)))
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func readExpectedChecksum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(b))
	if len(parts) == 0 {
		return "", fmt.Errorf("checksum file %s is empty", path)
	}
	return parts[0], nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}