// Package mcp implements the A5 MCP (Model Context Protocol) Gateway adapter.
//
// The MCP Gateway intercepts tool calls from MCP-compatible clients (Claude Desktop,
// Cursor, any MCP client) before they reach MCP tool servers. It acts as a
// transparent governance proxy: every tool invocation is authorized by Faramesh
// before the actual MCP server receives it.
//
// Architecture:
//
//	MCP Client ──► Faramesh MCP Gateway ──► Real MCP Server
//	              (governance here)
//
// The gateway implements the MCP protocol (JSON-RPC 2.0 over stdio or HTTP)
// and wraps the real MCP server's tools with governance. When a client calls
// a tool, the gateway:
//  1. Intercepts the tools/call message
//  2. Evaluates it through the Faramesh pipeline
//  3. If PERMIT: forwards to the real MCP server and returns the result
//  4. If DENY: returns an MCP error to the client (no forwarding)
//  5. If DEFER: returns a "pending approval" response with a polling token
//
// Usage (HTTP mode):
//
//	faramesh serve --policy policy.yaml --mcp-proxy-port 8090 --mcp-target http://localhost:3000
//
// Usage (stdio mode — wrap any stdio MCP server):
//
//	faramesh mcp wrap -- node mcp-server.js
//	# Then configure your MCP client to use: faramesh mcp wrap -- node mcp-server.js
//	# instead of: node mcp-server.js
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/google/uuid"
)

// MCPMessage is a JSON-RPC 2.0 message used by the MCP protocol.
type MCPMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError is a JSON-RPC 2.0 error object.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// toolCallParams is the params structure for tools/call requests.
type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// StdioGateway wraps a subprocess MCP server (stdio transport) with governance.
// The gateway reads from stdin, intercepts tool calls, and forwards to the subprocess.
type StdioGateway struct {
	pipeline *core.Pipeline
	agentID  string
	log      *zap.Logger

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner

	pendingMu sync.Mutex
	pending   map[any]chan MCPMessage // request ID → response channel

	nextID atomic.Int64
}

// NewStdioGateway creates a gateway that wraps a subprocess MCP server.
func NewStdioGateway(pipeline *core.Pipeline, agentID string, log *zap.Logger, cmdArgs []string) (*StdioGateway, error) {
	if len(cmdArgs) == 0 {
		return nil, fmt.Errorf("mcp gateway: at least one command argument required")
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp gateway stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp gateway stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp gateway start subprocess: %w", err)
	}

	g := &StdioGateway{
		pipeline: pipeline,
		agentID:  agentID,
		log:      log,
		cmd:      cmd,
		stdin:    stdin,
		stdout:   bufio.NewScanner(stdoutPipe),
		pending:  make(map[any]chan MCPMessage),
	}

	// Read responses from the subprocess and route them to waiting callers.
	go g.readSubprocessResponses()

	return g, nil
}

// ProcessRequest handles an inbound MCP message from the client.
// For tool calls: intercepts with governance. For other messages: passes through.
func (g *StdioGateway) ProcessRequest(msg MCPMessage) (MCPMessage, error) {
	if msg.Method == "tools/call" {
		return g.handleToolCall(msg)
	}
	// All other messages (initialize, tools/list, resources/*, prompts/*) pass through.
	return g.forwardToSubprocess(msg)
}

func (g *StdioGateway) handleToolCall(msg MCPMessage) (MCPMessage, error) {
	var params toolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return errorResponse(msg.ID, -32602, "invalid params: "+err.Error()), nil
	}

	car := core.CanonicalActionRequest{
		CallID:           uuid.New().String(),
		AgentID:          g.agentID,
		SessionID:        g.agentID + "-mcp",
		ToolID:           params.Name,
		Args:             params.Arguments,
		Timestamp:        time.Now(),
		InterceptAdapter: "mcp",
	}

	decision := g.pipeline.Evaluate(car)

	g.log.Info("mcp tool governed",
		zap.String("tool", params.Name),
		zap.String("effect", string(decision.Effect)),
		zap.Duration("latency", decision.Latency),
	)

	switch decision.Effect {
	case core.EffectPermit, core.EffectShadow:
		// Forward to the real MCP server.
		return g.forwardToSubprocess(msg)

	case core.EffectDeny:
		return errorResponse(msg.ID, -32003,
			fmt.Sprintf("Faramesh: tool call denied [%s] %s", decision.ReasonCode, decision.Reason)), nil

	case core.EffectDefer:
		// Return a pending approval response. The client must poll for resolution.
		result := map[string]any{
			"status":      "pending_approval",
			"defer_token": decision.DeferToken,
			"reason":      decision.Reason,
			"message":     fmt.Sprintf("Tool call requires human approval. Token: %s", decision.DeferToken),
		}
		resultBytes, _ := json.Marshal(result)
		return MCPMessage{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  resultBytes,
		}, nil
	}

	return errorResponse(msg.ID, -32000, "faramesh: unexpected decision effect"), nil
}

// forwardToSubprocess sends a request to the wrapped subprocess and waits for the response.
func (g *StdioGateway) forwardToSubprocess(msg MCPMessage) (MCPMessage, error) {
	// Assign a new ID for the subprocess request to avoid collision.
	subID := g.nextID.Add(1)
	origID := msg.ID
	msg.ID = subID

	ch := make(chan MCPMessage, 1)
	g.pendingMu.Lock()
	g.pending[subID] = ch
	g.pendingMu.Unlock()

	b, err := json.Marshal(msg)
	if err != nil {
		return MCPMessage{}, fmt.Errorf("marshal to subprocess: %w", err)
	}
	b = append(b, '\n')
	if _, err := g.stdin.Write(b); err != nil {
		return MCPMessage{}, fmt.Errorf("write to subprocess: %w", err)
	}

	// Wait for response with timeout.
	select {
	case resp := <-ch:
		resp.ID = origID // Restore the original client ID.
		return resp, nil
	case <-time.After(30 * time.Second):
		g.pendingMu.Lock()
		delete(g.pending, subID)
		g.pendingMu.Unlock()
		return errorResponse(origID, -32001, "faramesh: MCP server response timeout"), nil
	}
}

func (g *StdioGateway) readSubprocessResponses() {
	for g.stdout.Scan() {
		line := g.stdout.Bytes()
		var msg MCPMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		g.pendingMu.Lock()
		ch, ok := g.pending[msg.ID]
		if ok {
			delete(g.pending, msg.ID)
		}
		g.pendingMu.Unlock()
		if ok {
			ch <- msg
		}
	}
}

// Close shuts down the gateway and the wrapped subprocess.
func (g *StdioGateway) Close() error {
	_ = g.stdin.Close()
	return g.cmd.Process.Kill()
}

// HTTPGateway exposes an HTTP endpoint that proxies MCP-over-HTTP with governance.
// Configure your MCP client to point at the gateway URL instead of the real server.
type HTTPGateway struct {
	pipeline  *core.Pipeline
	agentID   string
	targetURL string
	log       *zap.Logger
	client    *http.Client
	httpSrv   *http.Server
}

// NewHTTPGateway creates an HTTP proxy gateway for MCP-over-HTTP servers.
func NewHTTPGateway(pipeline *core.Pipeline, agentID, targetURL string, log *zap.Logger) *HTTPGateway {
	g := &HTTPGateway{
		pipeline:  pipeline,
		agentID:   agentID,
		targetURL: targetURL,
		log:       log,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.handleMCP)
	g.httpSrv = &http.Server{Handler: mux}
	return g
}

// Listen starts the HTTP gateway on the given address.
func (g *HTTPGateway) Listen(addr string) error {
	g.httpSrv.Addr = addr
	g.log.Info("MCP HTTP gateway listening",
		zap.String("addr", addr),
		zap.String("target", g.targetURL),
	)
	go func() {
		if err := g.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			g.log.Error("MCP HTTP gateway error", zap.Error(err))
		}
	}()
	return nil
}

func (g *HTTPGateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var msg MCPMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
		return
	}

	// Only intercept tool calls. Everything else is forwarded.
	if msg.Method == "tools/call" {
		var params toolCallParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			http.Error(w, "invalid params", http.StatusBadRequest)
			return
		}

		car := core.CanonicalActionRequest{
			CallID:           uuid.New().String(),
			AgentID:          g.agentID,
			SessionID:        g.agentID + "-mcp-http",
			ToolID:           params.Name,
			Args:             params.Arguments,
			Timestamp:        time.Now(),
			InterceptAdapter: "mcp",
		}

		decision := g.pipeline.Evaluate(car)

		switch decision.Effect {
		case core.EffectDeny:
			resp := errorResponse(msg.ID, -32003,
				fmt.Sprintf("Faramesh: tool call denied [%s] %s", decision.ReasonCode, decision.Reason))
			writeJSONResponse(w, resp)
			return
		case core.EffectDefer:
			result := map[string]any{
				"status":      "pending_approval",
				"defer_token": decision.DeferToken,
				"message":     "Tool call requires human approval. Token: " + decision.DeferToken,
			}
			resultBytes, _ := json.Marshal(result)
			resp := MCPMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultBytes}
			writeJSONResponse(w, resp)
			return
		case core.EffectPermit, core.EffectShadow:
			// Fall through to forward.
		}
	}

	// Forward to the real MCP server.
	proxyReq, err := http.NewRequest(r.Method, g.targetURL+r.URL.Path, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "proxy request build failed", http.StatusInternalServerError)
		return
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			proxyReq.Header.Add(k, v)
		}
	}

	resp, err := g.client.Do(proxyReq)
	if err != nil {
		http.Error(w, "upstream MCP server error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// Close shuts down the gateway.
func (g *HTTPGateway) Close() error { return g.httpSrv.Close() }

func writeJSONResponse(w http.ResponseWriter, msg MCPMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(msg)
}

func errorResponse(id any, code int, message string) MCPMessage {
	return MCPMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &MCPError{Code: code, Message: message},
	}
}
