package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/fatih/color"
)

var (
	daemonAddr         string
	daemonSocket       string
	daemonHTTPFallback bool
	daemonHTTPClient   = &http.Client{Timeout: 30 * time.Second}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&daemonAddr, "addr", "", "daemon HTTP address (used only with --http-fallback)")
	rootCmd.PersistentFlags().StringVar(&daemonSocket, "daemon-socket", sdk.SocketPath, "daemon Unix socket path")
	rootCmd.PersistentFlags().BoolVar(&daemonHTTPFallback, "http-fallback", false, "allow fallback to HTTP control API when socket control call fails")
}

func daemonURL(path string) string {
	addr := strings.TrimRight(daemonAddr, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return addr + path
}

func daemonPost(path string, payload any) (json.RawMessage, error) {
	addr, err := resolveDaemonHTTPAddr()
	if err != nil {
		return nil, err
	}

	var reqBody io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}
	resp, err := daemonHTTPClient.Post(daemonURL(path), "application/json", reqBody)
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon at %s: %w", addr, err)
	}
	defer resp.Body.Close()
	return readDaemonResponse(resp)
}

func daemonGet(path string) (json.RawMessage, error) {
	addr, err := resolveDaemonHTTPAddr()
	if err != nil {
		return nil, err
	}

	resp, err := daemonHTTPClient.Get(daemonURL(path))
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon at %s: %w", addr, err)
	}
	defer resp.Body.Close()
	return readDaemonResponse(resp)
}

func daemonGetWithQuery(path string, query map[string]string) (json.RawMessage, error) {
	addr, err := resolveDaemonHTTPAddr()
	if err != nil {
		return nil, err
	}

	u := daemonURL(path)
	if len(query) > 0 {
		params := url.Values{}
		for k, v := range query {
			if v != "" {
				params.Set(k, v)
			}
		}
		if encoded := params.Encode(); encoded != "" {
			u += "?" + encoded
		}
	}
	resp, err := daemonHTTPClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon at %s: %w", addr, err)
	}
	defer resp.Body.Close()
	return readDaemonResponse(resp)
}

func resolveDaemonHTTPAddr() (string, error) {
	addr := strings.TrimSpace(daemonAddr)
	if addr == "" {
		return "", fmt.Errorf("HTTP fallback requires --addr to be set")
	}
	return addr, nil
}

func daemonSocketRequest(msg map[string]any) (json.RawMessage, error) {
	socketPath := resolveDaemonSocketPreference(strings.TrimSpace(os.Getenv("FARAMESH_SOCKET")))
	return daemonSocketRequestWithPath(socketPath, msg)
}

func daemonSocketRequestWithPath(socketPath string, msg map[string]any) (json.RawMessage, error) {
	typ, _ := msg["type"].(string)
	if strings.TrimSpace(typ) == "" {
		return nil, fmt.Errorf("socket request missing type")
	}
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = sdk.SocketPath
	}

	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot reach daemon socket at %s: %w", socketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("set socket deadline: %w", err)
	}

	line, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal socket request: %w", err)
	}
	line = append(line, '\n')
	if _, err := conn.Write(line); err != nil {
		return nil, fmt.Errorf("send socket request: %w", err)
	}

	raw, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read socket response: %w", err)
	}
	raw = bytes.TrimSpace(raw)

	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("invalid socket response: %w", err)
	}
	if emsg, _ := probe["error"].(string); strings.TrimSpace(emsg) != "" {
		return nil, fmt.Errorf("daemon socket error: %s", emsg)
	}

	return json.RawMessage(raw), nil
}

func daemonSocketRequestAt(socketPath string, msg map[string]any) (json.RawMessage, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return daemonSocketRequest(msg)
	}
	return daemonSocketRequestWithPath(socketPath, msg)
}

func resolveDaemonSocketPreference(envSocket string) string {
	configuredSocket := strings.TrimSpace(daemonSocket)
	if configuredSocket == "" {
		configuredSocket = sdk.SocketPath
	}
	envSocket = strings.TrimSpace(envSocket)

	if isPersistentFlagExplicitlySet("daemon-socket") {
		return configuredSocket
	}
	if envSocket != "" {
		return envSocket
	}
	if state, ok := readCurrentRuntimeStartState(); ok {
		if socket := strings.TrimSpace(state.SocketPath); socket != "" {
			return socket
		}
	}
	return configuredSocket
}

func isPersistentFlagExplicitlySet(name string) bool {
	if rootCmd == nil {
		return false
	}
	flag := rootCmd.PersistentFlags().Lookup(name)
	return flag != nil && flag.Changed
}

func readCurrentRuntimeStartState() (runtimeStartState, bool) {
	metaPath := filepath.Join(runtimeStateDirPath(""), "runtime.json")
	state, err := readRuntimeStartState(metaPath)
	if err != nil {
		return runtimeStartState{}, false
	}
	return state, true
}

func runtimeStateDirPath(raw string) string {
	dir := strings.TrimSpace(raw)
	if dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(os.TempDir(), "faramesh", "runtime")
	}
	return filepath.Join(home, ".faramesh", "runtime")
}

func readDaemonResponse(resp *http.Response) (json.RawMessage, error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("daemon returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	return json.RawMessage(raw), nil
}

var headerColor = color.New(color.Bold, color.FgCyan)

func printHeader(header string) {
	headerColor.Fprintf(os.Stdout, "\n%s\n", header)
	fmt.Fprintln(os.Stdout, strings.Repeat("─", len(header)))
}

func printJSON(data json.RawMessage) {
	if len(data) == 0 {
		color.New(color.FgGreen).Fprintln(os.Stdout, "  OK")
		fmt.Println()
		return
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "  ", "  "); err != nil {
		fmt.Fprintf(os.Stdout, "  %s\n\n", strings.TrimSpace(string(data)))
		return
	}
	fmt.Fprintf(os.Stdout, "  %s\n\n", pretty.String())
}

func printResponse(header string, raw json.RawMessage) {
	printHeader(header)
	printJSON(raw)
}
