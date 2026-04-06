package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	defaultLocalVaultAddr  = "http://127.0.0.1:18200"
	defaultLocalVaultToken = "root"
	defaultVaultMount      = "secret"
)

type vaultStatePaths struct {
	Dir       string
	PIDFile   string
	LogFile   string
	EnvFile   string
	TokenFile string
}

type vaultStatus struct {
	Address    string `json:"address"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"status_code,omitempty"`
	PID        int    `json:"pid,omitempty"`
	PIDAlive   bool   `json:"pid_alive,omitempty"`
	StateDir   string `json:"state_dir,omitempty"`
}

var (
	credVaultAddr        string
	credVaultToken       string
	credVaultMount       string
	credVaultNamespace   string
	credVaultStateDir    string
	credVaultJSON        bool
	credVaultToolField   string
	credVaultValue       string
	credVaultExternal    bool
	credVaultLocalToken  string
	credVaultUpAddr      string
	credVaultUpToken     string
	credVaultUpStateDir  string
	credVaultUpJSON      bool
	credVaultStatusAddr  string
	credVaultStatusToken string
	credVaultStatusState string
	credVaultStatusJSON  bool
	credVaultDownState   string
	credVaultDownJSON    bool
)

var credentialVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Provision and manage Vault for hard secret boundaries",
	Long: `Manage local and external Vault integration for credential broker workflows.

Use vault put to securely capture a key and store it under the broker lookup
path used by governed tool calls.

Default local path layout:
  mount/data/faramesh/<tool-id>

Example:
  faramesh credential vault put stripe/refund
  faramesh credential vault put stripe/refund --external --vault-addr http://vault.local:8200 --vault-token <token>`,
}

var credentialVaultUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Provision local dev Vault for Faramesh",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		addr := strings.TrimSpace(credVaultUpAddr)
		if addr == "" {
			addr = defaultLocalVaultAddr
		}
		token := strings.TrimSpace(credVaultUpToken)
		if token == "" {
			token = defaultLocalVaultToken
		}
		state, err := resolveVaultStatePaths(credVaultUpStateDir)
		if err != nil {
			return err
		}
		started, err := ensureLocalVaultRunning(addr, token, state)
		if err != nil {
			return err
		}
		if err := writeLocalVaultEnv(state, addr, token, defaultVaultMount); err != nil {
			return err
		}
		statusCode := 0
		healthy, sc := vaultHealthy(addr, token)
		statusCode = sc
		pid, pidAlive := readPIDState(state.PIDFile)
		resp := vaultStatus{Address: addr, Healthy: healthy, StatusCode: statusCode, PID: pid, PIDAlive: pidAlive, StateDir: state.Dir}
		if credVaultUpJSON {
			return printJSONReport(resp)
		}
		if started {
			fmt.Printf("local vault started at %s\n", addr)
		} else {
			fmt.Printf("local vault already healthy at %s\n", addr)
		}
		fmt.Printf("state dir: %s\n", state.Dir)
		fmt.Printf("env file: %s\n", state.EnvFile)
		fmt.Printf("use with daemon: faramesh serve --vault-addr %s --vault-token <token> --vault-mount %s ...\n", addr, defaultVaultMount)
		return nil
	},
}

var credentialVaultStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show local/external Vault health status",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		addr := strings.TrimSpace(credVaultStatusAddr)
		if addr == "" {
			addr = firstNonEmpty(
				strings.TrimSpace(os.Getenv("VAULT_ADDR")),
				strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_ADDR")),
				defaultLocalVaultAddr,
			)
		}
		token := strings.TrimSpace(credVaultStatusToken)
		if token == "" {
			token = firstNonEmpty(
				strings.TrimSpace(os.Getenv("VAULT_TOKEN")),
				strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_TOKEN")),
				defaultLocalVaultToken,
			)
		}
		state, err := resolveVaultStatePaths(credVaultStatusState)
		if err != nil {
			return err
		}
		healthy, statusCode := vaultHealthy(addr, token)
		pid, pidAlive := readPIDState(state.PIDFile)
		resp := vaultStatus{Address: addr, Healthy: healthy, StatusCode: statusCode, PID: pid, PIDAlive: pidAlive, StateDir: state.Dir}
		if credVaultStatusJSON {
			return printJSONReport(resp)
		}
		fmt.Printf("address: %s\n", resp.Address)
		fmt.Printf("healthy: %t\n", resp.Healthy)
		if resp.StatusCode > 0 {
			fmt.Printf("status code: %d\n", resp.StatusCode)
		}
		if resp.PID > 0 {
			fmt.Printf("local pid: %d (alive=%t)\n", resp.PID, resp.PIDAlive)
		}
		fmt.Printf("state dir: %s\n", resp.StateDir)
		return nil
	},
}

var credentialVaultDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop locally provisioned dev Vault",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		state, err := resolveVaultStatePaths(credVaultDownState)
		if err != nil {
			return err
		}
		pid, alive := readPIDState(state.PIDFile)
		if pid <= 0 || !alive {
			_ = os.Remove(state.PIDFile)
			if credVaultDownJSON {
				return printJSONReport(map[string]any{"stopped": false, "reason": "no running local vault pid"})
			}
			fmt.Println("no running local vault pid found")
			return nil
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("find vault pid %d: %w", pid, err)
		}
		if runtime.GOOS == "windows" {
			if err := proc.Kill(); err != nil {
				return fmt.Errorf("kill vault pid %d: %w", pid, err)
			}
		} else {
			if err := proc.Kill(); err != nil {
				return fmt.Errorf("kill vault pid %d: %w", pid, err)
			}
		}
		_ = os.Remove(state.PIDFile)
		if credVaultDownJSON {
			return printJSONReport(map[string]any{"stopped": true, "pid": pid})
		}
		fmt.Printf("stopped local vault pid %d\n", pid)
		return nil
	},
}

var credentialVaultPutCmd = &cobra.Command{
	Use:   "put <tool-id>",
	Short: "Prompt for a key and store it in Vault for brokered tool calls",
	Long: `Stores a secret at the broker lookup path for a governed tool.

Path written:
  <mount>/data/faramesh/<tool-id>

Default behavior provisions local Vault automatically if no Vault address is
provided. Use --external to require an already-running external Vault.

Examples:
  faramesh credential vault put stripe/refund
  faramesh credential vault put stripe/refund --external --vault-addr http://vault.local:8200 --vault-token <token>`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		toolID, err := normalizeVaultToolID(args[0])
		if err != nil {
			return err
		}
		secret := strings.TrimSpace(credVaultValue)
		if secret == "" {
			secret, err = readSecretPrompt(fmt.Sprintf("Enter secret for %s: ", toolID))
			if err != nil {
				return err
			}
		}
		if secret == "" {
			return fmt.Errorf("secret value cannot be empty")
		}

		addr := firstNonEmpty(
			strings.TrimSpace(credVaultAddr),
			strings.TrimSpace(os.Getenv("VAULT_ADDR")),
			strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_ADDR")),
		)
		token := firstNonEmpty(
			strings.TrimSpace(credVaultToken),
			strings.TrimSpace(os.Getenv("VAULT_TOKEN")),
			strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_TOKEN")),
		)
		mount := strings.TrimSpace(credVaultMount)
		if mount == "" {
			mount = defaultVaultMount
		}
		field := strings.TrimSpace(credVaultToolField)
		if field == "" {
			field = "value"
		}

		state, err := resolveVaultStatePaths(credVaultStateDir)
		if err != nil {
			return err
		}
		localProvisioned := false
		if addr == "" {
			if credVaultExternal {
				return fmt.Errorf("--external requires --vault-addr/VAULT_ADDR and --vault-token/VAULT_TOKEN")
			}
			addr = defaultLocalVaultAddr
			if token == "" {
				token = defaultLocalVaultToken
			}
			started, err := ensureLocalVaultRunning(addr, token, state)
			if err != nil {
				return err
			}
			localProvisioned = started
			if err := writeLocalVaultEnv(state, addr, token, mount); err != nil {
				return err
			}
		}
		if token == "" {
			return fmt.Errorf("vault token is required (use --vault-token or VAULT_TOKEN)")
		}
		if err := putVaultSecret(addr, token, strings.TrimSpace(credVaultNamespace), mount, toolID, field, secret); err != nil {
			return err
		}
		secret = ""

		path := vaultDataWritePath(mount, toolID)
		if credVaultJSON {
			return printJSONReport(map[string]any{
				"ok":                true,
				"tool_id":           toolID,
				"vault_addr":        addr,
				"vault_path":        path,
				"field":             field,
				"local_provisioned": localProvisioned,
				"env_file":          state.EnvFile,
			})
		}
		fmt.Printf("stored secret for %s at %s\n", toolID, path)
		fmt.Printf("vault addr: %s\n", addr)
		if localProvisioned {
			fmt.Printf("local vault provisioned: yes (state: %s)\n", state.Dir)
		} else {
			fmt.Printf("local vault provisioned: no\n")
		}
		fmt.Printf("start daemon with broker backend:\n")
		fmt.Printf("  faramesh serve --vault-addr %s --vault-token <token> --vault-mount %s --policy <policy> ...\n", addr, mount)
		fmt.Printf("then run agent with ambient key stripping:\n")
		fmt.Printf("  faramesh run --broker --agent-id <id> -- python your_agent.py\n")
		return nil
	},
}

func init() {
	credentialVaultUpCmd.Flags().StringVar(&credVaultUpAddr, "vault-addr", defaultLocalVaultAddr, "local Vault address (http://host:port)")
	credentialVaultUpCmd.Flags().StringVar(&credVaultUpToken, "vault-token", defaultLocalVaultToken, "local Vault root token for dev mode")
	credentialVaultUpCmd.Flags().StringVar(&credVaultUpStateDir, "state-dir", "", "state directory for local Vault pid/log/env files")
	credentialVaultUpCmd.Flags().BoolVar(&credVaultUpJSON, "json", false, "emit machine-readable JSON output")

	credentialVaultStatusCmd.Flags().StringVar(&credVaultStatusAddr, "vault-addr", "", "Vault address override (defaults to env/local)")
	credentialVaultStatusCmd.Flags().StringVar(&credVaultStatusToken, "vault-token", "", "Vault token override (defaults to env/local)")
	credentialVaultStatusCmd.Flags().StringVar(&credVaultStatusState, "state-dir", "", "state directory for local Vault pid/log/env files")
	credentialVaultStatusCmd.Flags().BoolVar(&credVaultStatusJSON, "json", false, "emit machine-readable JSON output")

	credentialVaultDownCmd.Flags().StringVar(&credVaultDownState, "state-dir", "", "state directory for local Vault pid/log/env files")
	credentialVaultDownCmd.Flags().BoolVar(&credVaultDownJSON, "json", false, "emit machine-readable JSON output")

	credentialVaultPutCmd.Flags().StringVar(&credVaultAddr, "vault-addr", "", "Vault address (defaults to local provisioning if unset)")
	credentialVaultPutCmd.Flags().StringVar(&credVaultToken, "vault-token", "", "Vault token (defaults to local token when provisioning locally)")
	credentialVaultPutCmd.Flags().StringVar(&credVaultMount, "vault-mount", defaultVaultMount, "Vault mount path for KV v2")
	credentialVaultPutCmd.Flags().StringVar(&credVaultNamespace, "vault-namespace", "", "Vault enterprise namespace")
	credentialVaultPutCmd.Flags().StringVar(&credVaultStateDir, "state-dir", "", "state directory for local Vault pid/log/env files")
	credentialVaultPutCmd.Flags().StringVar(&credVaultToolField, "field", "value", "field name to write in the Vault secret payload")
	credentialVaultPutCmd.Flags().StringVar(&credVaultValue, "value", "", "secret value (if omitted, prompt securely)")
	credentialVaultPutCmd.Flags().BoolVar(&credVaultExternal, "external", false, "require existing external Vault and disable local auto-provision")
	credentialVaultPutCmd.Flags().BoolVar(&credVaultJSON, "json", false, "emit machine-readable JSON output")

	credentialVaultCmd.AddCommand(credentialVaultUpCmd)
	credentialVaultCmd.AddCommand(credentialVaultStatusCmd)
	credentialVaultCmd.AddCommand(credentialVaultDownCmd)
	credentialVaultCmd.AddCommand(credentialVaultPutCmd)
}

func resolveVaultStatePaths(raw string) (vaultStatePaths, error) {
	dir := strings.TrimSpace(raw)
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			dir = filepath.Join(os.TempDir(), "faramesh", "local-vault")
		} else {
			dir = filepath.Join(home, ".faramesh", "local-vault")
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return vaultStatePaths{}, fmt.Errorf("create vault state dir: %w", err)
	}
	return vaultStatePaths{
		Dir:       dir,
		PIDFile:   filepath.Join(dir, "vault.pid"),
		LogFile:   filepath.Join(dir, "vault.log"),
		EnvFile:   filepath.Join(dir, "vault.env"),
		TokenFile: filepath.Join(dir, "vault.token"),
	}, nil
}

func ensureLocalVaultRunning(addr, token string, state vaultStatePaths) (bool, error) {
	healthy, _ := vaultHealthy(addr, token)
	if healthy {
		return false, nil
	}
	if _, err := exec.LookPath("vault"); err != nil {
		return false, fmt.Errorf("vault CLI is required for local provisioning (install: brew install hashicorp/tap/vault)")
	}
	listen, err := vaultListenAddress(addr)
	if err != nil {
		return false, err
	}
	pid, err := startLocalVaultProcess(listen, token, state)
	if err != nil {
		return false, err
	}
	if err := waitForVaultReady(addr, token, 20*time.Second); err != nil {
		return false, fmt.Errorf("vault pid %d failed readiness: %w", pid, err)
	}
	return true, nil
}

func startLocalVaultProcess(listen, token string, state vaultStatePaths) (int, error) {
	logFile, err := os.OpenFile(state.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open vault log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command("vault", "server", "-dev", "-dev-root-token-id", token, "-dev-listen-address", listen)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start local vault: %w", err)
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(state.PIDFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("write vault pid file: %w", err)
	}
	if err := os.WriteFile(state.TokenFile, []byte(token+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("write vault token file: %w", err)
	}
	_ = cmd.Process.Release()
	return pid, nil
}

func waitForVaultReady(addr, token string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastCode int
	for time.Now().Before(deadline) {
		healthy, code := vaultHealthy(addr, token)
		lastCode = code
		if healthy {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	if lastCode > 0 {
		return fmt.Errorf("vault health endpoint returned %d until timeout", lastCode)
	}
	return fmt.Errorf("vault did not become reachable within %s", timeout)
}

func vaultHealthy(addr, token string) (bool, int) {
	u := strings.TrimRight(strings.TrimSpace(addr), "/") + "/v1/sys/health"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return false, 0
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := (&http.Client{Timeout: 1500 * time.Millisecond}).Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	code := resp.StatusCode
	switch code {
	case http.StatusOK, 429, 472, 473, 501:
		return true, code
	default:
		return false, code
	}
}

func putVaultSecret(addr, token, namespace, mount, toolID, field, value string) error {
	path := vaultDataWritePath(mount, toolID)
	u := strings.TrimRight(strings.TrimSpace(addr), "/") + "/v1/" + path
	payload := map[string]any{
		"data": map[string]string{
			field:   value,
			"value": value,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal vault payload: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(namespace) != "" {
		req.Header.Set("X-Vault-Namespace", strings.TrimSpace(namespace))
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("vault write request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("vault write failed at %s with status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

func vaultDataWritePath(mount, toolID string) string {
	m := strings.Trim(strings.TrimSpace(mount), "/")
	if m == "" {
		m = defaultVaultMount
	}
	t := strings.Trim(strings.TrimSpace(toolID), "/")
	return m + "/data/faramesh/" + t
}

func normalizeVaultToolID(raw string) (string, error) {
	v := strings.Trim(strings.TrimSpace(raw), "/")
	if v == "" {
		return "", fmt.Errorf("tool-id cannot be empty")
	}
	if strings.Contains(v, "..") {
		return "", fmt.Errorf("tool-id cannot contain '..'")
	}
	parts := strings.Split(v, "/")
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return "", fmt.Errorf("tool-id has empty path segment")
		}
	}
	return v, nil
}

func vaultListenAddress(addr string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(addr))
	if err != nil {
		return "", fmt.Errorf("invalid vault address %q: %w", addr, err)
	}
	if u.Scheme != "http" {
		return "", fmt.Errorf("local vault provisioning only supports http:// addresses")
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("vault address must include host:port")
	}
	if strings.TrimSpace(u.Path) != "" && strings.TrimSpace(u.Path) != "/" {
		return "", fmt.Errorf("vault address must not include a path")
	}
	return u.Host, nil
}

func readSecretPrompt(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}
		return strings.TrimSpace(string(raw)), nil
	}
	return "", fmt.Errorf("interactive secret prompt requires a terminal; provide --value for non-interactive use")
}

func writeLocalVaultEnv(state vaultStatePaths, addr, token, mount string) error {
	content := fmt.Sprintf(
		"export VAULT_ADDR=%q\nexport VAULT_TOKEN=%q\nexport FARAMESH_CREDENTIAL_VAULT_ADDR=%q\nexport FARAMESH_CREDENTIAL_VAULT_TOKEN=%q\nexport FARAMESH_CREDENTIAL_VAULT_MOUNT=%q\n",
		addr,
		token,
		addr,
		token,
		mount,
	)
	if err := os.WriteFile(state.EnvFile, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write vault env file: %w", err)
	}
	return nil
}

func readPIDState(path string) (int, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}
	if runtime.GOOS == "windows" {
		err = proc.Signal(syscall.Signal(0))
		if err == nil {
			return pid, true
		}
		return pid, false
	}
	err = proc.Signal(syscall.Signal(0))
	return pid, err == nil
}

func printJSONReport(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json report: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
