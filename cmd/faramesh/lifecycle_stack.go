package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type stackServiceMode string

const (
	stackServiceModeAuto stackServiceMode = "auto"
	stackServiceModeOn   stackServiceMode = "on"
	stackServiceModeOff  stackServiceMode = "off"
)

var (
	upCmd = &cobra.Command{
		Use:   "up",
		Short: "Start the Faramesh runtime",
		Long:  "Start runtime governance services for policy enforcement, approvals, and evidence capture.",
		Args:  cobra.NoArgs,
		RunE:  runUp,
	}

	downCmd = &cobra.Command{
		Use:   "down",
		Short: "Stop the Faramesh runtime",
		Long:  "Stop runtime governance services and shut down managed local components.",
		Args:  cobra.NoArgs,
		RunE:  runDown,
	}

	upPolicy                 string
	upMode                   string
	upSocket                 string
	upDataDir                string
	upStateDir               string
	upRuntimeOnly            bool
	upVisibilityModeRaw      string
	upDashboardModeRaw       string
	upVisibilityHost         string
	upVisibilityPort         int
	upVisibilityDir          string
	upDashboardHost          string
	upDashboardPort          int
	upDashboardDir           string
	upVisibilityRefreshDeps  bool
	upDashboardRefreshDeps   bool
	upOpenApprovals          bool
	upRequireHealthyServices bool

	downStateDir    string
	downRuntimeOnly bool
	downPurgeState  bool
)

type visibilityServiceConfig struct {
	Mode         stackServiceMode
	Dir          string
	Host         string
	Port         int
	SocketPath   string
	CoreDir      string
	DPRDBPath    string
	StateDBPath  string
	PIDFile      string
	LogFile      string
	RefreshDeps  bool
	RequireReady bool
}

type dashboardServiceConfig struct {
	Mode          stackServiceMode
	Dir           string
	Host          string
	Port          int
	VisibilityURL string
	PIDFile       string
	LogFile       string
	RefreshDeps   bool
	RequireReady  bool
}

func init() {
	upCmd.Flags().StringVar(&upPolicy, "policy", "", "policy path (auto-detected when omitted)")
	upCmd.Flags().StringVar(&upMode, "mode", "enforce", "governance mode (advanced): enforce|shadow|audit")
	upCmd.Flags().StringVar(&upSocket, "socket", "", "daemon Unix socket path (defaults to --daemon-socket)")
	upCmd.Flags().StringVar(&upDataDir, "data-dir", "", "daemon data directory")
	upCmd.Flags().StringVar(&upStateDir, "state-dir", "", "runtime state directory")
	upCmd.Flags().BoolVar(&upRuntimeOnly, "runtime-only", false, "start only the governance runtime")
	upCmd.Flags().StringVar(&upVisibilityModeRaw, "visibility", "auto", "visibility service mode: auto|on|off")
	upCmd.Flags().StringVar(&upDashboardModeRaw, "dashboard", "auto", "dashboard service mode: auto|on|off")
	upCmd.Flags().StringVar(&upVisibilityHost, "visibility-host", "127.0.0.1", "visibility bind host")
	upCmd.Flags().IntVar(&upVisibilityPort, "visibility-port", 8787, "visibility bind port")
	upCmd.Flags().StringVar(&upVisibilityDir, "visibility-dir", "", "visibility service directory override")
	upCmd.Flags().StringVar(&upDashboardHost, "dashboard-host", "127.0.0.1", "dashboard bind host")
	upCmd.Flags().IntVar(&upDashboardPort, "dashboard-port", 3000, "dashboard bind port")
	upCmd.Flags().StringVar(&upDashboardDir, "dashboard-dir", "", "dashboard directory override")
	upCmd.Flags().BoolVar(&upVisibilityRefreshDeps, "refresh-visibility-deps", false, "reinstall visibility Python dependencies before startup")
	upCmd.Flags().BoolVar(&upDashboardRefreshDeps, "refresh-dashboard-deps", false, "reinstall dashboard Node dependencies before startup")
	upCmd.Flags().BoolVar(&upOpenApprovals, "open-approvals", false, "open the approvals UI in the default browser after startup")
	upCmd.Flags().BoolVar(&upRequireHealthyServices, "require-healthy-services", false, "fail if optional visibility/dashboard services are unavailable")

	downCmd.Flags().StringVar(&downStateDir, "state-dir", "", "runtime state directory")
	downCmd.Flags().BoolVar(&downRuntimeOnly, "runtime-only", false, "stop only the governance runtime")
	downCmd.Flags().BoolVar(&downPurgeState, "purge-state", false, "remove runtime metadata and pid files after shutdown")

	// Keep infrastructure controls for advanced/operator workflows only.
	_ = upCmd.Flags().MarkHidden("socket")
	_ = upCmd.Flags().MarkHidden("data-dir")
	_ = upCmd.Flags().MarkHidden("state-dir")
	_ = upCmd.Flags().MarkHidden("mode")
	_ = upCmd.Flags().MarkHidden("runtime-only")
	_ = upCmd.Flags().MarkHidden("visibility")
	_ = upCmd.Flags().MarkHidden("dashboard")
	_ = upCmd.Flags().MarkHidden("visibility-host")
	_ = upCmd.Flags().MarkHidden("visibility-port")
	_ = upCmd.Flags().MarkHidden("visibility-dir")
	_ = upCmd.Flags().MarkHidden("dashboard-host")
	_ = upCmd.Flags().MarkHidden("dashboard-port")
	_ = upCmd.Flags().MarkHidden("dashboard-dir")
	_ = upCmd.Flags().MarkHidden("refresh-visibility-deps")
	_ = upCmd.Flags().MarkHidden("refresh-dashboard-deps")
	_ = upCmd.Flags().MarkHidden("require-healthy-services")

	_ = downCmd.Flags().MarkHidden("state-dir")
	_ = downCmd.Flags().MarkHidden("runtime-only")
	_ = downCmd.Flags().MarkHidden("purge-state")

	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(downCmd)
}

func runUp(_ *cobra.Command, _ []string) error {
	visibilityMode, err := parseStackServiceMode(upVisibilityModeRaw)
	if err != nil {
		return err
	}
	dashboardMode, err := parseStackServiceMode(upDashboardModeRaw)
	if err != nil {
		return err
	}

	if upRuntimeOnly {
		visibilityMode = stackServiceModeOff
		dashboardMode = stackServiceModeOff
	}

	socketPath := strings.TrimSpace(upSocket)
	if socketPath == "" {
		socketPath = resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
	}
	if socketPath == "" {
		socketPath = defaultDaemonSocketPath()
	}

	daemonResult, err := ensureDaemonStarted(daemonStartOptions{
		PolicyPath: upPolicy,
		Mode:       upMode,
		SocketPath: socketPath,
		DataDir:    upDataDir,
		StateDir:   upStateDir,
	})
	if err != nil {
		return err
	}

	state := daemonResult.State
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve cwd: %w", err)
	}

	visibilityDir := resolveServiceDir(cwd, upVisibilityDir, "FARAMESH_VISIBILITY_DIR", []string{
		"faramesh-core/visibility-server",
		"visibility-server",
	})
	coreDir := ""
	if visibilityDir != "" {
		coreDir = filepath.Dir(visibilityDir)
	}
	if coreDir == "" {
		if found := resolveServiceDir(cwd, "", "FARAMESH_CORE_DIR", []string{"faramesh-core"}); found != "" {
			coreDir = found
		}
	}
	if coreDir == "" {
		coreDir = cwd
	}

	visibilityState, visErr := ensureVisibilityService(visibilityServiceConfig{
		Mode:         visibilityMode,
		Dir:          visibilityDir,
		Host:         upVisibilityHost,
		Port:         upVisibilityPort,
		SocketPath:   state.SocketPath,
		CoreDir:      coreDir,
		DPRDBPath:    filepath.Join(state.DataDir, "faramesh.db"),
		StateDBPath:  filepath.Join(daemonResult.StateDir, "visibility", "visibility.db"),
		PIDFile:      filepath.Join(daemonResult.StateDir, "visibility.pid"),
		LogFile:      filepath.Join(daemonResult.StateDir, "visibility.log"),
		RefreshDeps:  upVisibilityRefreshDeps,
		RequireReady: upRequireHealthyServices,
	})
	if visErr != nil {
		return visErr
	}
	state.Visibility = &visibilityState

	visibilityURL := firstNonEmpty(visibilityState.URL, fmt.Sprintf("http://%s:%d", upVisibilityHost, upVisibilityPort))
	dashboardDir := resolveServiceDir(cwd, upDashboardDir, "FARAMESH_DASHBOARD_DIR", []string{
		"Faramesh-cloud-platform/client",
		"client",
	})
	dashboardState, dashboardErr := ensureDashboardService(dashboardServiceConfig{
		Mode:          dashboardMode,
		Dir:           dashboardDir,
		Host:          upDashboardHost,
		Port:          upDashboardPort,
		VisibilityURL: visibilityURL,
		PIDFile:       filepath.Join(daemonResult.StateDir, "dashboard.pid"),
		LogFile:       filepath.Join(daemonResult.StateDir, "dashboard.log"),
		RefreshDeps:   upDashboardRefreshDeps,
		RequireReady:  upRequireHealthyServices,
	})
	if dashboardErr != nil {
		return dashboardErr
	}
	state.Dashboard = &dashboardState
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := writeRuntimeStartState(daemonResult.MetaPath, state); err != nil {
		return fmt.Errorf("write runtime state: %w", err)
	}

	if daemonResult.AlreadyRunning {
		fmt.Printf("runtime: running (pid=%d, socket=%s)\n", state.DaemonPID, state.SocketPath)
	} else {
		fmt.Printf("runtime: started (pid=%d, socket=%s)\n", state.DaemonPID, state.SocketPath)
	}
	fmt.Printf("policy: %s\n", state.PolicyPath)
	if daemonResult.BootstrappedPolicy {
		fmt.Printf("policy bootstrap: created starter policy at %s\n", state.PolicyPath)
	}
	fmt.Printf("mode: %s\n", state.Mode)

	printManagedServiceSummary("visibility", visibilityState)
	printManagedServiceSummary("dashboard", dashboardState)

	if dashboardState.Running {
		approvalsURL := strings.TrimRight(dashboardState.URL, "/") + "/approvals"
		fmt.Printf("approvals UI: %s\n", approvalsURL)
		if upOpenApprovals {
			if err := openBrowserURL(approvalsURL); err != nil {
				return fmt.Errorf("open approvals UI: %w", err)
			}
		}
	} else {
		fmt.Println("approvals UI: use 'faramesh approvals ui' for dashboard or built-in fallback")
	}

	return nil
}

func runDown(_ *cobra.Command, _ []string) error {
	stateDir, err := resolveRuntimeStateDir(downStateDir)
	if err != nil {
		return err
	}

	metaPath := filepath.Join(stateDir, "runtime.json")
	state := runtimeStartState{}
	if loaded, loadErr := readRuntimeStartState(metaPath); loadErr == nil {
		state = loaded
	}

	if !downRuntimeOnly {
		if stopped, stopErr := stopManagedService("dashboard", state.Dashboard, filepath.Join(stateDir, "dashboard.pid")); stopErr != nil {
			return stopErr
		} else if stopped {
			fmt.Println("dashboard: stopped")
		}

		if stopped, stopErr := stopManagedService("visibility", state.Visibility, filepath.Join(stateDir, "visibility.pid")); stopErr != nil {
			return stopErr
		} else if stopped {
			fmt.Println("visibility: stopped")
		}
	}

	socketPath := strings.TrimSpace(state.SocketPath)
	if socketPath == "" {
		socketPath = resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
	}

	shutdownErr := requestDaemonShutdown(socketPath)
	if shutdownErr == nil {
		fmt.Println("runtime: shutdown initiated")
		if state.DaemonPID > 0 {
			if !waitForCondition(6*time.Second, 200*time.Millisecond, func() bool {
				return !isProcessAlive(state.DaemonPID)
			}) {
				if err := terminatePID(state.DaemonPID); err != nil {
					return fmt.Errorf("stop daemon pid %d: %w", state.DaemonPID, err)
				}
				fmt.Printf("runtime: stopped by pid (%d)\n", state.DaemonPID)
			}
		}
	} else if state.DaemonPID > 0 && isProcessAlive(state.DaemonPID) {
		if err := terminatePID(state.DaemonPID); err != nil {
			return fmt.Errorf("stop daemon pid %d: %w", state.DaemonPID, err)
		}
		fmt.Printf("runtime: stopped by pid (%d)\n", state.DaemonPID)
	} else {
		fmt.Println("runtime: no active daemon detected")
	}

	if socketPath != "" && (state.DaemonPID <= 0 || !isProcessAlive(state.DaemonPID)) {
		_ = os.Remove(socketPath)
	}

	_ = os.Remove(filepath.Join(stateDir, "daemon.pid"))
	if downPurgeState {
		_ = os.Remove(filepath.Join(stateDir, "visibility.pid"))
		_ = os.Remove(filepath.Join(stateDir, "dashboard.pid"))
		_ = os.Remove(metaPath)
		fmt.Printf("state: purged (%s)\n", stateDir)
		return nil
	}

	state.DaemonPID = 0
	if state.Visibility != nil {
		state.Visibility.Running = false
		state.Visibility.PID = 0
	}
	if state.Dashboard != nil {
		state.Dashboard.Running = false
		state.Dashboard.PID = 0
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeRuntimeStartState(metaPath, state); err != nil {
		return fmt.Errorf("write runtime state: %w", err)
	}
	return nil
}

func parseStackServiceMode(raw string) (stackServiceMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto":
		return stackServiceModeAuto, nil
	case "on", "true", "yes":
		return stackServiceModeOn, nil
	case "off", "false", "no":
		return stackServiceModeOff, nil
	default:
		return "", fmt.Errorf("invalid service mode %q (expected auto|on|off)", raw)
	}
}

func resolveServiceDir(cwd, explicit, envVar string, suffixCandidates []string) string {
	if raw := normalizeExistingDir(explicit); raw != "" {
		return raw
	}

	if envVar != "" {
		if raw := normalizeExistingDir(os.Getenv(envVar)); raw != "" {
			return raw
		}
	}

	for _, suffix := range suffixCandidates {
		suffix = strings.TrimSpace(suffix)
		if suffix == "" {
			continue
		}

		candidate := suffix
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, suffix)
		}
		if found := normalizeExistingDir(candidate); found != "" {
			return found
		}
	}
	return ""
}

func normalizeExistingDir(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if abs, err := filepath.Abs(raw); err == nil {
		raw = abs
	}
	if dirExists(raw) {
		return raw
	}
	return ""
}

func ensureVisibilityService(cfg visibilityServiceConfig) (managedServiceState, error) {
	state := managedServiceState{Enabled: cfg.Mode != stackServiceModeOff}
	if cfg.Mode == stackServiceModeOff {
		return state, nil
	}
	if cfg.Dir == "" {
		if cfg.Mode == stackServiceModeOn || cfg.RequireReady {
			return state, fmt.Errorf("visibility service directory not found (use --visibility-dir or set FARAMESH_VISIBILITY_DIR)")
		}
		state.Enabled = false
		state.Error = "visibility service not discovered"
		return state, nil
	}

	url := fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port)
	state.URL = url
	if visibilityHealthOK(url) {
		state.Running = true
		state.Managed = false
		return state, nil
	}

	if tcpPortListening(cfg.Host, cfg.Port) {
		if cfg.Mode == stackServiceModeOn || cfg.RequireReady {
			return state, fmt.Errorf("visibility port %d is busy but service is unhealthy", cfg.Port)
		}
		state.Error = fmt.Sprintf("port %d busy with non-ready service", cfg.Port)
		return state, nil
	}

	if !socketStatusOK(cfg.SocketPath) {
		return state, fmt.Errorf("visibility requires reachable daemon socket at %s", cfg.SocketPath)
	}

	pythonPath, err := ensureVisibilityPython(cfg.Dir, cfg.RefreshDeps)
	if err != nil {
		return state, err
	}

	if err := os.MkdirAll(filepath.Dir(cfg.StateDBPath), 0o755); err != nil {
		return state, fmt.Errorf("create visibility state dir: %w", err)
	}

	args := []string{"-m", "uvicorn", "app.main:app", "--host", cfg.Host, "--port", strconv.Itoa(cfg.Port)}
	cmd := exec.Command(pythonPath, args...)
	cmd.Dir = cfg.Dir
	cmd.Env = mergeEnv(os.Environ(), []string{
		"FARAMESH_SOCKET=" + cfg.SocketPath,
		"FARAMESH_DPR_DB=" + cfg.DPRDBPath,
		"FARAMESH_CORE_DIR=" + cfg.CoreDir,
		"FARAMESH_VISIBILITY_DB=" + cfg.StateDBPath,
	})
	pid, err := startBackgroundProcess(cmd, cfg.LogFile, cfg.PIDFile)
	if err != nil {
		return state, err
	}

	if !waitForCondition(20*time.Second, 250*time.Millisecond, func() bool {
		return visibilityHealthOK(url)
	}) {
		_ = terminatePID(pid)
		return state, fmt.Errorf("visibility failed readiness at %s/health", url)
	}

	state.Running = true
	state.Managed = true
	state.PID = pid
	state.LogPath = cfg.LogFile
	return state, nil
}

func ensureDashboardService(cfg dashboardServiceConfig) (managedServiceState, error) {
	state := managedServiceState{Enabled: cfg.Mode != stackServiceModeOff}
	if cfg.Mode == stackServiceModeOff {
		return state, nil
	}
	if cfg.Dir == "" {
		if cfg.Mode == stackServiceModeOn || cfg.RequireReady {
			return state, fmt.Errorf("dashboard directory not found (use --dashboard-dir or set FARAMESH_DASHBOARD_DIR)")
		}
		state.Enabled = false
		state.Error = "dashboard not discovered"
		return state, nil
	}

	url := fmt.Sprintf("http://%s:%d", cfg.Host, cfg.Port)
	state.URL = url
	if dashboardHealthOK(url) {
		state.Running = true
		state.Managed = false
		return state, nil
	}

	if tcpPortListening(cfg.Host, cfg.Port) {
		if cfg.Mode == stackServiceModeOn || cfg.RequireReady {
			return state, fmt.Errorf("dashboard port %d is busy but service is unhealthy", cfg.Port)
		}
		state.Error = fmt.Sprintf("port %d busy with non-ready dashboard service", cfg.Port)
		return state, nil
	}

	pkgManager, err := resolveDashboardPackageManager(cfg.Dir)
	if err != nil {
		return state, err
	}
	if err := ensureDashboardDependencies(cfg.Dir, pkgManager, cfg.RefreshDeps); err != nil {
		return state, err
	}

	devArgs := []string{"run", "dev"}
	cmd := exec.Command(pkgManager, devArgs...)
	cmd.Dir = cfg.Dir
	cmd.Env = mergeEnv(os.Environ(), []string{
		"NUXT_HOST=" + cfg.Host,
		"NUXT_PORT=" + strconv.Itoa(cfg.Port),
		"HOST=" + cfg.Host,
		"PORT=" + strconv.Itoa(cfg.Port),
		"FARAMESH_CONTROL_PLANE_LOCAL_FALLBACK_ENABLED=true",
		"FARAMESH_CONTROL_PLANE_VISIBILITY_BRIDGE_ENABLED=true",
		"FARAMESH_VISIBILITY_BASE_URL=" + cfg.VisibilityURL,
	})

	pid, err := startBackgroundProcess(cmd, cfg.LogFile, cfg.PIDFile)
	if err != nil {
		return state, err
	}

	if !waitForCondition(35*time.Second, 300*time.Millisecond, func() bool {
		return dashboardHealthOK(url)
	}) {
		_ = terminatePID(pid)
		return state, fmt.Errorf("dashboard failed readiness at %s/api/control-plane/v1/health", url)
	}

	state.Running = true
	state.Managed = true
	state.PID = pid
	state.LogPath = cfg.LogFile
	return state, nil
}

func ensureVisibilityPython(visibilityDir string, refreshDeps bool) (string, error) {
	venvPython := filepath.Join(visibilityDir, ".venv", "bin", "python")
	if runtime.GOOS == "windows" {
		venvPython = filepath.Join(visibilityDir, ".venv", "Scripts", "python.exe")
	}

	if !fileExists(venvPython) {
		if err := runCommand(visibilityDir, nil, "python3", "-m", "venv", ".venv"); err != nil {
			return "", fmt.Errorf("create visibility virtualenv: %w", err)
		}
	}

	reqPath := filepath.Join(visibilityDir, "requirements.txt")
	hash, err := fileSHA256(reqPath)
	if err != nil {
		return "", fmt.Errorf("hash visibility requirements: %w", err)
	}
	stampPath := filepath.Join(visibilityDir, ".venv", ".faramesh_requirements.sha256")
	stampRaw, _ := os.ReadFile(stampPath)
	needsInstall := strings.TrimSpace(string(stampRaw)) != hash
	if refreshDeps {
		needsInstall = true
	}

	if needsInstall {
		if err := runCommand(visibilityDir, nil, venvPython, "-m", "pip", "install", "-r", "requirements.txt"); err != nil {
			return "", fmt.Errorf("install visibility dependencies: %w", err)
		}
		_ = os.WriteFile(stampPath, []byte(hash+"\n"), 0o600)
	}

	return venvPython, nil
}

func resolveDashboardPackageManager(dir string) (string, error) {
	if fileExists(filepath.Join(dir, "pnpm-lock.yaml")) {
		if _, err := exec.LookPath("pnpm"); err == nil {
			return "pnpm", nil
		}
	}
	if _, err := exec.LookPath("npm"); err == nil {
		return "npm", nil
	}
	if _, err := exec.LookPath("pnpm"); err == nil {
		return "pnpm", nil
	}
	return "", fmt.Errorf("neither npm nor pnpm found in PATH for dashboard startup")
}

func ensureDashboardDependencies(dir, pkgManager string, refresh bool) error {
	if !refresh && dirExists(filepath.Join(dir, "node_modules")) {
		return nil
	}
	installArgs := []string{"install"}
	if err := runCommand(dir, nil, pkgManager, installArgs...); err != nil {
		return fmt.Errorf("install dashboard dependencies: %w", err)
	}
	return nil
}

func runCommand(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = env
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, trimmed)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
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

func startBackgroundProcess(cmd *exec.Cmd, logPath, pidPath string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return 0, fmt.Errorf("create log dir: %w", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open log file: %w", err)
	}
	defer logFile.Close()

	applyProcessGroup(cmd)

	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start process: %w", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("write pid file: %w", err)
	}
	return pid, nil
}

func waitForCondition(timeout, interval time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(interval)
	}
	return fn()
}

func tcpPortListening(host string, port int) bool {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func visibilityHealthOK(baseURL string) bool {
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}
	ok := asBool(payload["ok"], false)
	daemonOK := asBool(payload["daemon_ok"], true)
	return ok && daemonOK
}

func dashboardHealthOK(baseURL string) bool {
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	endpoints := []string{
		"/api/control-plane/v1/health",
		"/api/control-plane/v1/orgs/org_dev_local/approval-requests?limit=1",
	}
	for _, endpoint := range endpoints {
		resp, err := client.Get(strings.TrimRight(baseURL, "/") + endpoint)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true
		}
	}
	return false
}

func asBool(value any, fallback bool) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		normalized := strings.ToLower(strings.TrimSpace(v))
		switch normalized {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		default:
			return fallback
		}
	default:
		return fallback
	}
}

func printManagedServiceSummary(name string, state managedServiceState) {
	if !state.Enabled {
		if strings.TrimSpace(state.Error) != "" {
			fmt.Printf("%s: skipped (%s)\n", name, state.Error)
		} else {
			fmt.Printf("%s: disabled\n", name)
		}
		return
	}
	if !state.Running {
		if strings.TrimSpace(state.Error) != "" {
			fmt.Printf("%s: unavailable (%s)\n", name, state.Error)
		} else {
			fmt.Printf("%s: unavailable\n", name)
		}
		return
	}
	mode := "external"
	if state.Managed {
		mode = "managed"
	}
	if state.URL != "" {
		fmt.Printf("%s: running (%s, %s)\n", name, mode, state.URL)
	} else {
		fmt.Printf("%s: running (%s)\n", name, mode)
	}
}

func stopManagedService(name string, state *managedServiceState, pidFile string) (bool, error) {
	pid := 0
	managed := false
	if state != nil {
		managed = state.Managed
		pid = state.PID
	}
	if pid <= 0 {
		if filePID, alive := readPIDState(pidFile); alive {
			pid = filePID
			managed = true
		}
	}
	if pid <= 0 {
		_ = os.Remove(pidFile)
		return false, nil
	}
	if !managed {
		return false, nil
	}
	if !isProcessAlive(pid) {
		_ = os.Remove(pidFile)
		return false, nil
	}
	if err := terminatePID(pid); err != nil {
		return false, fmt.Errorf("stop %s pid %d: %w", name, pid, err)
	}
	_ = os.Remove(pidFile)
	return true, nil
}

func requestDaemonShutdown(socketPath string) error {
	socket := strings.TrimSpace(socketPath)
	if socket == "" {
		socket = resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
	}

	_, err := daemonSocketRequestAt(socket, map[string]any{"type": "shutdown"})
	if err != nil && daemonHTTPFallback && strings.TrimSpace(daemonAddr) != "" {
		_, err = daemonPost("/api/v1/shutdown", nil)
	}
	return err
}

func openBrowserURL(target string) error {
	url := strings.TrimSpace(target)
	if url == "" {
		return fmt.Errorf("empty URL")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
