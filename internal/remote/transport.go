package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
)

// Transport resolves Unix socket (local daemon) vs HTTPS remote governance.
type Transport struct {
	SocketPath string
	RemoteURL  string
	Token      string
	HTTPClient *http.Client
}

// DetectTransport chooses transport from environment.
// Priority: FARAMESH_REMOTE_URL (HTTPS) > FARAMESH_SOCKET / default Unix socket.
func DetectTransport() (*Transport, error) {
	if u := strings.TrimSpace(os.Getenv("FARAMESH_REMOTE_URL")); u != "" {
		return &Transport{
			RemoteURL: strings.TrimRight(u, "/"),
			Token:     strings.TrimSpace(os.Getenv("FARAMESH_TOKEN")),
			HTTPClient: &http.Client{Timeout: 30 * time.Second},
		}, nil
	}
	socket := strings.TrimSpace(os.Getenv("FARAMESH_SOCKET"))
	if socket == "" {
		socket = "/tmp/faramesh.sock"
	}
	if _, err := os.Stat(socket); err != nil {
		if base := strings.TrimSpace(os.Getenv("FARAMESH_BASE_URL")); base != "" {
			return &Transport{
				RemoteURL: strings.TrimRight(base, "/"),
				Token:     strings.TrimSpace(os.Getenv("FARAMESH_TOKEN")),
				HTTPClient: &http.Client{Timeout: 30 * time.Second},
			}, nil
		}
		return nil, fmt.Errorf("no governance transport: set FARAMESH_SOCKET (%s missing) or FARAMESH_REMOTE_URL", socket)
	}
	return &Transport{SocketPath: socket}, nil
}

// Evaluate sends a CAR and returns a governance decision.
func (t *Transport) Evaluate(ctx context.Context, req core.CanonicalActionRequest) (core.Decision, error) {
	if t == nil {
		return core.Decision{}, fmt.Errorf("nil transport")
	}
	if t.RemoteURL != "" {
		return NewClient(t.RemoteURL, t.Token).Evaluate(ctx, req)
	}
	return t.evaluateSocket(ctx, req)
}

func (t *Transport) evaluateSocket(ctx context.Context, req core.CanonicalActionRequest) (core.Decision, error) {
	parts := strings.SplitN(strings.TrimSpace(req.ToolID), "/", 2)
	tool, op := req.ToolID, "invoke"
	if len(parts) == 2 {
		tool, op = parts[0], parts[1]
	}
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "govern",
		"params": map[string]any{
			"agent_id":    req.AgentID,
			"tool":        tool,
			"operation":   op,
			"session_id":  req.SessionID,
			"args":        req.Args,
			"action_type": string(core.NormalizeActionType(req.ActionType)),
		},
	}
	body, _ := json.Marshal(payload)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", t.SocketPath)
	if err != nil {
		return core.Decision{}, err
	}
	defer conn.Close()
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return core.Decision{}, err
	}
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		return core.Decision{}, err
	}
	var resp struct {
		Result core.Decision `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return core.Decision{}, err
	}
	if resp.Error != nil {
		return core.Decision{}, fmt.Errorf("socket govern: %s", resp.Error.Message)
	}
	return resp.Result, nil
}

// Mode returns "remote" or "socket".
func (t *Transport) Mode() string {
	if t != nil && t.RemoteURL != "" {
		return "remote"
	}
	return "socket"
}
