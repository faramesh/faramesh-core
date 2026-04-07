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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strings"
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
	outbound  chan []byte

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
		outbound: make(chan []byte, 128),
	}

	// Read responses from the subprocess and route them to waiting callers.
	go g.readSubprocessResponses()

	return g, nil
}

// ProcessRequest handles an inbound MCP message from the client.
// For tool calls: intercepts with governance. For other messages: passes through.
func (g *StdioGateway) ProcessRequest(msg MCPMessage) (MCPMessage, error) {
	if err := validateMCPMessage(msg); err != nil {
		return MCPMessage{}, err
	}
	kind := classifyMCPMessage(msg)
	if kind == mcpMessageRequest && msg.Method == "tools/call" {
		return g.handleToolCall(msg)
	}
	if kind == mcpMessageNotification || kind == mcpMessageResponse {
		if err := g.sendOneWayToSubprocess(msg); err != nil {
			return MCPMessage{}, err
		}
		return MCPMessage{}, nil
	}
	// All other messages (initialize, tools/list, resources/*, prompts/*) pass through.
	return g.forwardToSubprocess(msg)
}

// ProcessStdioLine parses one stdin line: a single JSON-RPC object or a JSON-RPC batch array.
// It returns one line of JSON (no trailing newline), or nil if the line is empty/whitespace.
// Batch semantics match HTTPGateway.handleMCPBatch: notifications are forwarded to the subprocess
// and omitted from the response array; call/response pairs are ordered.
func (g *StdioGateway) ProcessStdioLine(line []byte) ([]byte, error) {
	trim := bytes.TrimSpace(line)
	if len(trim) == 0 {
		return nil, nil
	}
	if trim[0] == '[' {
		return g.processStdioBatch(trim)
	}
	var msg MCPMessage
	if err := json.Unmarshal(trim, &msg); err != nil {
		return nil, err
	}
	out, err := g.ProcessRequest(msg)
	if err != nil {
		return nil, err
	}
	if isNoResponseMessage(out) {
		return nil, nil
	}
	return json.Marshal(out)
}

func (g *StdioGateway) processStdioBatch(body []byte) ([]byte, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC batch: %w", err)
	}
	out := make([]MCPMessage, 0, len(raw))
	for _, rawEl := range raw {
		var msg MCPMessage
		if err := json.Unmarshal(rawEl, &msg); err != nil {
			return nil, fmt.Errorf("invalid batch element: %w", err)
		}
		if err := validateMCPMessage(msg); err != nil {
			return nil, err
		}
		kind := classifyMCPMessage(msg)
		if kind == mcpMessageNotification || kind == mcpMessageResponse {
			if err := g.sendOneWayToSubprocess(msg); err != nil {
				return nil, err
			}
			continue
		}
		outMsg, err := g.ProcessRequest(msg)
		if err != nil {
			return nil, err
		}
		if isNoResponseMessage(outMsg) {
			continue
		}
		out = append(out, outMsg)
	}
	return json.Marshal(out)
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
		resp, err := g.forwardToSubprocess(msg)
		if err != nil {
			return resp, err
		}
		return applyPostScanMCPMessage(g.pipeline, params.Name, resp), nil

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

	if err := g.sendOneWayToSubprocess(msg); err != nil {
		g.pendingMu.Lock()
		delete(g.pending, subID)
		g.pendingMu.Unlock()
		return MCPMessage{}, err
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

func (g *StdioGateway) sendOneWayToSubprocess(msg MCPMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal to subprocess: %w", err)
	}
	b = append(b, '\n')
	if _, err := g.stdin.Write(b); err != nil {
		return fmt.Errorf("write to subprocess: %w", err)
	}
	return nil
}

func (g *StdioGateway) readSubprocessResponses() {
	defer close(g.outbound)
	for g.stdout.Scan() {
		line := append([]byte(nil), g.stdout.Bytes()...)
		var msg MCPMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			g.log.Debug("mcp stdio upstream emitted non-json line", zap.ByteString("line", line))
			continue
		}
		if msg.Method != "" {
			select {
			case g.outbound <- line:
			default:
				g.log.Warn("dropping outbound stdio MCP message due to full buffer",
					zap.String("method", msg.Method),
				)
			}
			continue
		}
		// JSON numbers decode as float64 into `any`; pending keys use int64 from atomic IDs.
		key := normalizeJSONRPCIDForPending(msg.ID)
		g.pendingMu.Lock()
		ch, ok := g.pending[key]
		if ok {
			delete(g.pending, key)
		}
		g.pendingMu.Unlock()
		if ok {
			ch <- msg
		}
	}
	if err := g.stdout.Err(); err != nil {
		g.log.Warn("mcp stdio subprocess reader stopped", zap.Error(err))
	}
}

func normalizeJSONRPCIDForPending(id any) any {
	switch x := id.(type) {
	case float64:
		if x == float64(int64(x)) {
			return int64(x)
		}
		return x
	default:
		return id
	}
}

// Close shuts down the gateway and the wrapped subprocess.
func (g *StdioGateway) Close() error {
	_ = g.stdin.Close()
	return g.cmd.Process.Kill()
}

// Outbound returns unsolicited upstream stdio messages (requests/notifications)
// that should be forwarded to the MCP client.
func (g *StdioGateway) Outbound() <-chan []byte {
	return g.outbound
}

// HTTPGateway exposes an HTTP endpoint that proxies MCP-over-HTTP with governance.
// Configure your MCP client to point at the gateway URL instead of the real server.
//
// Streamable HTTP (SSE): GET/HEAD/OPTIONS requests are proxied with httputil.ReverseProxy
// (FlushInterval set). JSON-RPC POST with Accept: text/event-stream streams the upstream
// response when permitted (tools/call governance still applies); deny/defer return JSON.
// Batch requests with SSE Accept are rejected. For text/event-stream responses, each line is
// scanned; `data:` lines that contain JSON-RPC MCP results run post-scan (same as buffered JSON).
type HTTPGateway struct {
	pipeline  *core.Pipeline
	agentID   string
	targetURL string
	log       *zap.Logger
	client    *http.Client
	revProxy  *httputil.ReverseProxy
	httpSrv   *http.Server
	origins   map[string]struct{}

	edgeAuthMode        mcpEdgeAuthMode
	edgeAuthBearerToken string

	protocolVersionMode mcpProtocolVersionMode
	protocolVersion     string

	sessionTTL         time.Duration
	sessionIdleTimeout time.Duration
	sessionMu          sync.Mutex
	sessionStates      map[string]gatewaySessionState

	sseReplayEnabled   bool
	sseReplayMaxEvents int
	sseReplayMaxAge    time.Duration
	sseReplayMu        sync.Mutex
	sseReplayEvents    map[string][]sseReplayEvent
	nextSSEReplayID    atomic.Int64
}

type mcpEdgeAuthMode int

const (
	mcpEdgeAuthOff mcpEdgeAuthMode = iota
	mcpEdgeAuthBearer
	mcpEdgeAuthMTLS
	mcpEdgeAuthBearerOrMTLS
)

type mcpProtocolVersionMode int

const (
	mcpProtocolVersionOff mcpProtocolVersionMode = iota
	mcpProtocolVersionStrict
)

type gatewaySessionState struct {
	createdAt time.Time
	lastSeen  time.Time
}

type sseReplayEvent struct {
	id        string
	payload   []byte
	createdAt time.Time
}

// HTTPGatewayConfig configures production hardening features on the MCP HTTP gateway.
type HTTPGatewayConfig struct {
	AllowedOrigins []string

	EdgeAuthMode        string
	EdgeAuthBearerToken string

	ProtocolVersionMode string
	ProtocolVersion     string

	SessionTTL         time.Duration
	SessionIdleTimeout time.Duration

	SSEReplayEnabled   bool
	SSEReplayMaxEvents int
	SSEReplayMaxAge    time.Duration
}

const (
	defaultMCPProtocolVersion = "2025-06-18"
	defaultSSEReplayMaxEvents = 256
	defaultSSEReplayMaxAge    = 10 * time.Minute
)

// NewHTTPGateway creates an HTTP proxy gateway for MCP-over-HTTP servers.
func NewHTTPGateway(pipeline *core.Pipeline, agentID, targetURL string, log *zap.Logger, allowedOrigins ...string) *HTTPGateway {
	return NewHTTPGatewayWithConfig(pipeline, agentID, targetURL, log, HTTPGatewayConfig{AllowedOrigins: allowedOrigins})
}

// NewHTTPGatewayWithConfig creates an HTTP proxy gateway for MCP-over-HTTP servers
// with optional production hardening controls.
func NewHTTPGatewayWithConfig(pipeline *core.Pipeline, agentID, targetURL string, log *zap.Logger, cfg HTTPGatewayConfig) *HTTPGateway {
	replayEnabled := cfg.SSEReplayEnabled
	replayMaxEvents := cfg.SSEReplayMaxEvents
	if replayEnabled && replayMaxEvents == 0 {
		replayMaxEvents = defaultSSEReplayMaxEvents
	}
	if replayMaxEvents < 0 {
		replayMaxEvents = 0
	}
	replayMaxAge := cfg.SSEReplayMaxAge
	if replayEnabled && replayMaxAge == 0 {
		replayMaxAge = defaultSSEReplayMaxAge
	}
	if replayMaxAge < 0 {
		replayMaxAge = 0
	}
	if replayMaxEvents == 0 {
		replayEnabled = false
	}

	g := &HTTPGateway{
		pipeline:  pipeline,
		agentID:   agentID,
		targetURL: targetURL,
		log:       log,
		origins:   normalizeAllowedOrigins(cfg.AllowedOrigins),
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		edgeAuthMode:        normalizeMCPEdgeAuthMode(cfg.EdgeAuthMode),
		edgeAuthBearerToken: strings.TrimSpace(cfg.EdgeAuthBearerToken),
		protocolVersionMode: normalizeMCPProtocolVersionMode(cfg.ProtocolVersionMode),
		protocolVersion:     normalizeMCPProtocolVersion(cfg.ProtocolVersion),
		sessionTTL:          cfg.SessionTTL,
		sessionIdleTimeout:  cfg.SessionIdleTimeout,
		sessionStates:       make(map[string]gatewaySessionState),
		sseReplayEnabled:    replayEnabled,
		sseReplayMaxEvents:  replayMaxEvents,
		sseReplayMaxAge:     replayMaxAge,
		sseReplayEvents:     make(map[string][]sseReplayEvent),
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		if log != nil {
			log.Warn("mcp http gateway: could not parse upstream URL; GET/HEAD/OPTIONS stream proxy disabled", zap.String("target", targetURL), zap.Error(err))
		}
	} else if u.Scheme != "" && u.Host != "" {
		rp := httputil.NewSingleHostReverseProxy(u)
		rp.FlushInterval = 100 * time.Millisecond
		g.revProxy = rp
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

// ListenTLS starts the HTTPS gateway on the given address.
func (g *HTTPGateway) ListenTLS(addr, certFile, keyFile string, tlsConfig *tls.Config) error {
	g.httpSrv.Addr = addr
	g.httpSrv.TLSConfig = tlsConfig
	g.log.Info("MCP HTTP gateway listening (tls)",
		zap.String("addr", addr),
		zap.String("target", g.targetURL),
	)
	go func() {
		if err := g.httpSrv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			g.log.Error("MCP HTTP gateway tls error", zap.Error(err))
		}
	}()
	return nil
}

func isStreamOrPreflightMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
		return true
	default:
		return false
	}
}

func acceptsEventStream(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
}

func (g *HTTPGateway) upstreamURL(r *http.Request) string {
	s := g.targetURL + r.URL.Path
	if r.URL.RawQuery != "" {
		s += "?" + r.URL.RawQuery
	}
	return s
}

func (g *HTTPGateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	if !g.isOriginAllowed(r) {
		http.Error(w, `{"error":"origin not allowed"}`, http.StatusForbidden)
		return
	}
	if err := g.enforceEdgeAuth(r); err != nil {
		if g.edgeAuthMode == mcpEdgeAuthBearer || g.edgeAuthMode == mcpEdgeAuthBearerOrMTLS {
			w.Header().Set("WWW-Authenticate", `Bearer realm="faramesh-mcp"`)
		}
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if err := g.validateProtocolVersionRequest(r); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	sessionID := g.sessionIDForRequest(r)
	if err := g.touchSessionLifecycle(r, sessionID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodDelete {
		g.terminateSession(sessionID)
	}

	// Streamable HTTP: subscription and preflight without JSON-RPC body.
	if isStreamOrPreflightMethod(r.Method) {
		if g.shouldUseCustomStreamProxy(r) {
			g.forwardMCPStream(w, r, nil, "", sessionID)
			return
		}
		if g.revProxy == nil {
			http.Error(w, "mcp gateway: stream proxy unavailable (invalid upstream URL)", http.StatusServiceUnavailable)
			return
		}
		g.revProxy.ServeHTTP(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	trim := bytes.TrimSpace(body)
	if len(trim) > 0 && trim[0] == '[' {
		if acceptsEventStream(r) {
			http.Error(w, "JSON-RPC batch with Accept: text/event-stream is not supported", http.StatusBadRequest)
			return
		}
		g.handleMCPBatch(w, r, body, sessionID)
		return
	}

	g.handleMCPSingle(w, r, body, sessionID)
}

func (g *HTTPGateway) handleMCPSingle(w http.ResponseWriter, r *http.Request, body []byte, sessionID string) {
	var msg MCPMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
		return
	}
	if err := validateMCPMessage(msg); err != nil {
		http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
		return
	}

	kind := classifyMCPMessage(msg)
	if kind == mcpMessageNotification || kind == mcpMessageResponse {
		g.forwardMCPAccepted(w, r, body)
		return
	}

	streamOut := acceptsEventStream(r)

	if msg.Method == "tools/call" {
		resp, forward, toolName, err := g.interceptToolsCall(msg, sessionID)
		if err != nil {
			http.Error(w, "invalid params", http.StatusBadRequest)
			return
		}
		if !forward {
			writeJSONResponse(w, *resp)
			return
		}
		if streamOut {
			// Streamable HTTP: upstream may return text/event-stream; post-scan applies only to buffered JSON bodies.
			g.forwardMCPStream(w, r, body, toolName, sessionID)
			return
		}
		g.forwardMCPWithPostScan(w, r, body, toolName)
		return
	}

	if streamOut {
		g.forwardMCPStream(w, r, body, "", sessionID)
		return
	}
	g.forwardMCPRaw(w, r, body)
}

// handleMCPBatch processes JSON-RPC 2.0 batch requests in order. Each element is handled
// independently: tools/call messages are governed; other methods are forwarded upstream
// one request at a time. Notifications (no id) are forwarded but omitted from the batch
// response, per JSON-RPC semantics.
func (g *HTTPGateway) handleMCPBatch(w http.ResponseWriter, r *http.Request, body []byte, sessionID string) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		http.Error(w, "invalid JSON-RPC batch", http.StatusBadRequest)
		return
	}
	out := make([]MCPMessage, 0, len(raw))
	for _, rawEl := range raw {
		var msg MCPMessage
		if err := json.Unmarshal(rawEl, &msg); err != nil {
			http.Error(w, "invalid batch element", http.StatusBadRequest)
			return
		}
		if err := validateMCPMessage(msg); err != nil {
			http.Error(w, "invalid batch element", http.StatusBadRequest)
			return
		}
		kind := classifyMCPMessage(msg)
		if kind == mcpMessageNotification || kind == mcpMessageResponse {
			if _, _, _, err := g.doUpstreamRequest(r, rawEl); err != nil {
				g.log.Error("upstream MCP server error", zap.Error(err))
				http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
				return
			}
			continue
		}
		if msg.Method == "tools/call" {
			resp, forward, toolName, err := g.interceptToolsCall(msg, sessionID)
			if err != nil {
				http.Error(w, "invalid params", http.StatusBadRequest)
				return
			}
			if !forward {
				out = append(out, *resp)
				continue
			}
			st, respBody, err := g.forwardMCPWithPostScanBytes(r, rawEl, toolName)
			if err != nil {
				g.log.Error("upstream MCP server error", zap.Error(err))
				http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
				return
			}
			var up MCPMessage
			if st == http.StatusOK && json.Unmarshal(respBody, &up) == nil {
				out = append(out, up)
			} else {
				out = append(out, *batchUpstreamError(msg.ID, st, respBody))
			}
			continue
		}
		st, respBody, _, err := g.doUpstreamRequest(r, rawEl)
		if err != nil {
			g.log.Error("upstream MCP server error", zap.Error(err))
			http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
			return
		}
		var up MCPMessage
		if st == http.StatusOK && json.Unmarshal(respBody, &up) == nil {
			out = append(out, up)
		} else {
			out = append(out, *batchUpstreamError(msg.ID, st, respBody))
		}
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

func batchUpstreamError(id any, st int, body []byte) *MCPMessage {
	msg := string(body)
	if len(msg) > 512 {
		msg = msg[:512] + "..."
	}
	return &MCPMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &MCPError{Code: -32000, Message: fmt.Sprintf("upstream http %d: %s", st, msg)},
	}
}

func (g *HTTPGateway) forwardMCPAccepted(w http.ResponseWriter, r *http.Request, body []byte) {
	st, respBody, _, err := g.doUpstreamRequest(r, body)
	if err != nil {
		g.log.Error("upstream MCP server error", zap.Error(err))
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	if st >= 200 && st < 300 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if len(respBody) == 0 {
		http.Error(w, http.StatusText(st), st)
		return
	}
	w.WriteHeader(st)
	_, _ = w.Write(respBody)
}

// doUpstreamRequest proxies one JSON-RPC payload to the MCP upstream and returns the body.
func (g *HTTPGateway) doUpstreamRequest(r *http.Request, body []byte) (statusCode int, respBody []byte, respHeader http.Header, err error) {
	proxyReq, err := http.NewRequest(r.Method, g.upstreamURL(r), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			proxyReq.Header.Add(k, v)
		}
	}
	resp, err := g.client.Do(proxyReq)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	if err := g.validateProtocolVersionResponse(resp.Header, r.Method); err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	return resp.StatusCode, b, resp.Header, nil
}

// forwardMCPStream proxies upstream and copies the response without buffering the full body.
// When the client sends Accept: text/event-stream, streamable HTTP servers may return long-lived
// SSE responses. For tools/call requests, JSON-RPC result payloads in SSE data lines are post-scanned.
func (g *HTTPGateway) forwardMCPStream(w http.ResponseWriter, r *http.Request, body []byte, toolID, sessionID string) {
	streamClient := &http.Client{
		Timeout:   0,
		Transport: g.client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if streamClient.Transport == nil {
		streamClient.Transport = http.DefaultTransport
	}
	lastEventID := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	replayPayloads, replayHit := g.replayEventsAfter(sessionID, lastEventID)

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, g.upstreamURL(r), bytes.NewReader(body))
	if err != nil {
		g.log.Error("failed to build upstream request", zap.Error(err))
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	for k, vs := range r.Header {
		if replayHit && strings.EqualFold(k, "Last-Event-ID") {
			continue
		}
		for _, v := range vs {
			proxyReq.Header.Add(k, v)
		}
	}
	proxyReq.ContentLength = int64(len(body))
	resp, err := streamClient.Do(proxyReq)
	if err != nil {
		g.log.Error("upstream MCP server error", zap.Error(err))
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if err := g.validateProtocolVersionResponse(resp.Header, r.Method); err != nil {
		g.log.Warn("upstream MCP protocol version validation failed", zap.Error(err))
		http.Error(w, `{"error":"upstream protocol version mismatch"}`, http.StatusBadGateway)
		return
	}
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		for _, payload := range replayPayloads {
			if _, err := w.Write(payload); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if err := g.streamSSEWithPostScan(w, resp.Body, toolID, sessionID); err != nil {
			return
		}
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func (g *HTTPGateway) streamSSEWithPostScan(w http.ResponseWriter, body io.Reader, toolID, sessionID string) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	eventLines := make([][]byte, 0, 8)

	flushEvent := func(lines [][]byte) error {
		if len(lines) == 0 {
			if _, err := w.Write([]byte("\n")); err != nil {
				return err
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return nil
		}

		outLines := make([][]byte, 0, len(lines)+1)
		eventID := ""
		for _, line := range lines {
			transformed := transformSSEDataLineForPostScan(line, toolID, g.pipeline)
			outLines = append(outLines, transformed)
			if id, ok := parseSSEEventID(transformed); ok {
				eventID = id
			}
		}
		if g.sseReplayEnabledForSession(sessionID) && eventID == "" {
			eventID = g.nextReplayEventID(sessionID)
			outLines = append([][]byte{[]byte("id: " + eventID)}, outLines...)
		}

		var payload bytes.Buffer
		for _, line := range outLines {
			if _, err := payload.Write(line); err != nil {
				return err
			}
			if err := payload.WriteByte('\n'); err != nil {
				return err
			}
		}
		if err := payload.WriteByte('\n'); err != nil {
			return err
		}
		if _, err := w.Write(payload.Bytes()); err != nil {
			return err
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if eventID != "" && g.sseReplayEnabledForSession(sessionID) {
			g.appendReplayEvent(sessionID, eventID, payload.Bytes())
		}
		return nil
	}

	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) == 0 {
			if err := flushEvent(eventLines); err != nil {
				return err
			}
			eventLines = eventLines[:0]
			continue
		}
		eventLines = append(eventLines, line)
	}
	if len(eventLines) > 0 {
		if err := flushEvent(eventLines); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// forwardMCPWithPostScanBytes is like forwardMCPWithPostScan but returns bytes for batch mode.
func (g *HTTPGateway) forwardMCPWithPostScanBytes(r *http.Request, body []byte, toolID string) (statusCode int, respBody []byte, err error) {
	st, b, _, err := g.doUpstreamRequest(r, body)
	if err != nil {
		return 0, nil, err
	}
	var respMsg MCPMessage
	if st == http.StatusOK && json.Unmarshal(b, &respMsg) == nil {
		respMsg = applyPostScanMCPMessage(g.pipeline, toolID, respMsg)
		if out, err := json.Marshal(respMsg); err == nil {
			b = out
		}
	}
	return st, b, nil
}

// interceptToolsCall evaluates tools/call. If forward is false, resp is the JSON-RPC response
// to return. If forward is true, the caller must forward body upstream (toolName for post-scan).
func (g *HTTPGateway) interceptToolsCall(msg MCPMessage, sessionID string) (resp *MCPMessage, forward bool, toolName string, err error) {
	var params toolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, false, "", err
	}
	scopedAgentID := fmt.Sprintf("%s#mcp-%s", g.agentID, stableSessionSuffix(sessionID))
	car := core.CanonicalActionRequest{
		CallID:           uuid.New().String(),
		AgentID:          scopedAgentID,
		SessionID:        sessionID,
		ToolID:           params.Name,
		Args:             params.Arguments,
		Timestamp:        time.Now(),
		InterceptAdapter: "mcp",
	}
	decision := g.pipeline.Evaluate(car)
	switch decision.Effect {
	case core.EffectDeny:
		r := errorResponse(msg.ID, -32003,
			fmt.Sprintf("Faramesh: tool call denied [%s] %s", decision.ReasonCode, decision.Reason))
		return &r, false, "", nil
	case core.EffectDefer:
		result := map[string]any{
			"status":      "pending_approval",
			"defer_token": decision.DeferToken,
			"message":     "Tool call requires human approval. Token: " + decision.DeferToken,
		}
		resultBytes, _ := json.Marshal(result)
		r := MCPMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultBytes}
		return &r, false, "", nil
	case core.EffectPermit, core.EffectShadow, core.EffectShadowPermit:
		return nil, true, params.Name, nil
	default:
		return nil, true, params.Name, nil
	}
}

// forwardMCPRaw proxies the request body to the upstream MCP server and copies the response.
func (g *HTTPGateway) forwardMCPRaw(w http.ResponseWriter, r *http.Request, body []byte) {
	st, respBody, hdr, err := g.doUpstreamRequest(r, body)
	if err != nil {
		g.log.Error("upstream MCP server error", zap.Error(err))
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	for k, vs := range hdr {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(st)
	_, _ = w.Write(respBody)
}

// forwardMCPWithPostScan forwards a tools/call that was PERMIT'd, then post-scans the JSON-RPC response body.
func (g *HTTPGateway) forwardMCPWithPostScan(w http.ResponseWriter, r *http.Request, body []byte, toolID string) {
	st, respBody, hdr, err := g.doUpstreamRequest(r, body)
	if err != nil {
		g.log.Error("upstream MCP server error", zap.Error(err))
		http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
		return
	}
	var respMsg MCPMessage
	if st == http.StatusOK && json.Unmarshal(respBody, &respMsg) == nil {
		respMsg = applyPostScanMCPMessage(g.pipeline, toolID, respMsg)
		if out, err := json.Marshal(respMsg); err == nil {
			respBody = out
		}
	}
	for k, vs := range hdr {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
	w.WriteHeader(st)
	_, _ = w.Write(respBody)
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

type mcpMessageKind int

const (
	mcpMessageInvalid mcpMessageKind = iota
	mcpMessageRequest
	mcpMessageNotification
	mcpMessageResponse
)

func classifyMCPMessage(msg MCPMessage) mcpMessageKind {
	method := strings.TrimSpace(msg.Method)
	hasID := msg.ID != nil
	if method != "" {
		if hasID {
			return mcpMessageRequest
		}
		return mcpMessageNotification
	}
	if hasID {
		if msg.Error != nil || len(msg.Result) > 0 {
			return mcpMessageResponse
		}
		return mcpMessageInvalid
	}
	return mcpMessageInvalid
}

func validateMCPMessage(msg MCPMessage) error {
	if strings.TrimSpace(msg.JSONRPC) != "2.0" {
		return fmt.Errorf("jsonrpc must be 2.0")
	}
	if classifyMCPMessage(msg) == mcpMessageInvalid {
		return fmt.Errorf("invalid JSON-RPC message shape")
	}
	return nil
}

func isNoResponseMessage(msg MCPMessage) bool {
	return msg.JSONRPC == "" && msg.ID == nil && msg.Method == "" && len(msg.Params) == 0 && len(msg.Result) == 0 && msg.Error == nil
}

func normalizeAllowedOrigins(allowedOrigins []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, raw := range allowedOrigins {
		candidate := strings.TrimSpace(raw)
		if candidate == "" {
			continue
		}
		if candidate == "*" {
			out[candidate] = struct{}{}
			continue
		}
		u, err := url.Parse(candidate)
		if err != nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
			continue
		}
		out[strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host)] = struct{}{}
	}
	return out
}

func (g *HTTPGateway) isOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return false
	}
	if _, ok := g.origins["*"]; ok {
		return true
	}
	canonical := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	if _, ok := g.origins[canonical]; ok {
		return true
	}
	originHost := hostOnly(u.Host)
	requestHost := hostOnly(r.Host)
	if originHost != "" && originHost == requestHost {
		return true
	}
	if originHost == "localhost" {
		return true
	}
	if ip := net.ParseIP(originHost); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func (g *HTTPGateway) shouldUseCustomStreamProxy(r *http.Request) bool {
	if g.protocolVersionMode == mcpProtocolVersionStrict {
		return true
	}
	if g.sseReplayEnabled && r.Method == http.MethodGet && acceptsEventStream(r) {
		return true
	}
	return false
}

func (g *HTTPGateway) enforceEdgeAuth(r *http.Request) error {
	switch g.edgeAuthMode {
	case mcpEdgeAuthOff:
		return nil
	case mcpEdgeAuthBearer:
		if g.isValidBearerToken(r) {
			return nil
		}
		return fmt.Errorf("missing or invalid bearer token")
	case mcpEdgeAuthMTLS:
		if hasVerifiedPeerCertificate(r.TLS) {
			return nil
		}
		return fmt.Errorf("mTLS client certificate required")
	case mcpEdgeAuthBearerOrMTLS:
		if g.isValidBearerToken(r) || hasVerifiedPeerCertificate(r.TLS) {
			return nil
		}
		return fmt.Errorf("bearer token or mTLS client certificate required")
	default:
		return nil
	}
}

func (g *HTTPGateway) isValidBearerToken(r *http.Request) bool {
	expected := strings.TrimSpace(g.edgeAuthBearerToken)
	if expected == "" {
		return false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	return strings.TrimSpace(parts[1]) == expected
}

func hasVerifiedPeerCertificate(cs *tls.ConnectionState) bool {
	if cs == nil {
		return false
	}
	if len(cs.VerifiedChains) > 0 {
		return true
	}
	return len(cs.PeerCertificates) > 0
}

func (g *HTTPGateway) validateProtocolVersionRequest(r *http.Request) error {
	if g.protocolVersionMode != mcpProtocolVersionStrict {
		return nil
	}
	if r.Method == http.MethodOptions {
		return nil
	}
	actual := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	if actual == "" {
		return fmt.Errorf("missing MCP-Protocol-Version header")
	}
	if actual != g.protocolVersion {
		return fmt.Errorf("unsupported MCP-Protocol-Version %q", actual)
	}
	return nil
}

func (g *HTTPGateway) validateProtocolVersionResponse(hdr http.Header, method string) error {
	if g.protocolVersionMode != mcpProtocolVersionStrict {
		return nil
	}
	if method == http.MethodOptions {
		return nil
	}
	actual := strings.TrimSpace(hdr.Get("MCP-Protocol-Version"))
	if actual == "" {
		return fmt.Errorf("upstream missing MCP-Protocol-Version header")
	}
	if actual != g.protocolVersion {
		return fmt.Errorf("upstream returned unsupported MCP-Protocol-Version %q", actual)
	}
	return nil
}

func (g *HTTPGateway) touchSessionLifecycle(r *http.Request, sessionID string) error {
	if strings.TrimSpace(r.Header.Get("Mcp-Session-Id")) == "" {
		return nil
	}
	if g.sessionTTL <= 0 && g.sessionIdleTimeout <= 0 {
		return nil
	}
	now := time.Now()
	g.sessionMu.Lock()
	defer g.sessionMu.Unlock()
	state, ok := g.sessionStates[sessionID]
	if !ok {
		g.sessionStates[sessionID] = gatewaySessionState{createdAt: now, lastSeen: now}
		return nil
	}
	if g.sessionTTL > 0 && now.Sub(state.createdAt) > g.sessionTTL {
		delete(g.sessionStates, sessionID)
		return fmt.Errorf("mcp session expired")
	}
	if g.sessionIdleTimeout > 0 && now.Sub(state.lastSeen) > g.sessionIdleTimeout {
		delete(g.sessionStates, sessionID)
		return fmt.Errorf("mcp session idle timeout exceeded")
	}
	state.lastSeen = now
	g.sessionStates[sessionID] = state
	return nil
}

func (g *HTTPGateway) pruneExpiredSessionsLocked(now time.Time) {
	if g.sessionTTL <= 0 && g.sessionIdleTimeout <= 0 {
		return
	}
	for sessionID, st := range g.sessionStates {
		if g.sessionTTL > 0 && now.Sub(st.createdAt) > g.sessionTTL {
			delete(g.sessionStates, sessionID)
			continue
		}
		if g.sessionIdleTimeout > 0 && now.Sub(st.lastSeen) > g.sessionIdleTimeout {
			delete(g.sessionStates, sessionID)
		}
	}
}

func (g *HTTPGateway) terminateSession(sessionID string) {
	g.sessionMu.Lock()
	delete(g.sessionStates, sessionID)
	g.sessionMu.Unlock()

	g.sseReplayMu.Lock()
	delete(g.sseReplayEvents, sessionID)
	g.sseReplayMu.Unlock()
}

func (g *HTTPGateway) replayEventsAfter(sessionID, lastEventID string) ([][]byte, bool) {
	if !g.sseReplayEnabledForSession(sessionID) {
		return nil, false
	}
	lastEventID = strings.TrimSpace(lastEventID)
	if lastEventID == "" {
		return nil, false
	}
	now := time.Now()
	g.sseReplayMu.Lock()
	defer g.sseReplayMu.Unlock()
	g.pruneReplayEventsLocked(now)
	events := g.sseReplayEvents[sessionID]
	idx := -1
	for i, event := range events {
		if event.id == lastEventID {
			idx = i
			break
		}
	}
	if idx == -1 || idx+1 >= len(events) {
		return nil, idx != -1
	}
	out := make([][]byte, 0, len(events)-idx-1)
	for _, event := range events[idx+1:] {
		out = append(out, append([]byte(nil), event.payload...))
	}
	return out, true
}

func (g *HTTPGateway) appendReplayEvent(sessionID, eventID string, payload []byte) {
	if !g.sseReplayEnabledForSession(sessionID) {
		return
	}
	copyPayload := append([]byte(nil), payload...)
	now := time.Now()
	g.sseReplayMu.Lock()
	defer g.sseReplayMu.Unlock()
	g.pruneReplayEventsLocked(now)
	events := append(g.sseReplayEvents[sessionID], sseReplayEvent{id: eventID, payload: copyPayload, createdAt: now})
	if max := g.sseReplayMaxEvents; max > 0 && len(events) > max {
		events = events[len(events)-max:]
	}
	g.sseReplayEvents[sessionID] = events
}

func (g *HTTPGateway) pruneReplayEventsLocked(now time.Time) {
	if g.sseReplayMaxAge <= 0 {
		return
	}
	for sessionID, events := range g.sseReplayEvents {
		filtered := events[:0]
		for _, event := range events {
			if now.Sub(event.createdAt) <= g.sseReplayMaxAge {
				filtered = append(filtered, event)
			}
		}
		if len(filtered) == 0 {
			delete(g.sseReplayEvents, sessionID)
			continue
		}
		g.sseReplayEvents[sessionID] = filtered
	}
}

func (g *HTTPGateway) sseReplayEnabledForSession(sessionID string) bool {
	return g.sseReplayEnabled && g.sseReplayMaxEvents > 0 && strings.TrimSpace(sessionID) != ""
}

func (g *HTTPGateway) nextReplayEventID(sessionID string) string {
	n := g.nextSSEReplayID.Add(1)
	return fmt.Sprintf("%s-%d", stableSessionSuffix(sessionID), n)
}

func parseSSEEventID(line []byte) (string, bool) {
	if len(line) < 3 {
		return "", false
	}
	if !((line[0] == 'i' || line[0] == 'I') && (line[1] == 'd' || line[1] == 'D') && line[2] == ':') {
		return "", false
	}
	id := strings.TrimSpace(string(line[3:]))
	if id == "" {
		return "", false
	}
	return id, true
}

func normalizeMCPEdgeAuthMode(raw string) mcpEdgeAuthMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return mcpEdgeAuthOff
	case "bearer":
		return mcpEdgeAuthBearer
	case "mtls":
		return mcpEdgeAuthMTLS
	case "bearer_or_mtls":
		return mcpEdgeAuthBearerOrMTLS
	default:
		return mcpEdgeAuthOff
	}
}

func normalizeMCPProtocolVersionMode(raw string) mcpProtocolVersionMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return mcpProtocolVersionOff
	case "strict":
		return mcpProtocolVersionStrict
	default:
		return mcpProtocolVersionOff
	}
}

func normalizeMCPProtocolVersion(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return defaultMCPProtocolVersion
	}
	return value
}

func (g *HTTPGateway) sessionIDForRequest(r *http.Request) string {
	if sid := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); sid != "" {
		return fmt.Sprintf("%s-mcp-http-%s", g.agentID, stableSessionSuffix(sid))
	}
	remoteHost := hostOnly(r.RemoteAddr)
	if remoteHost == "" {
		remoteHost = "unknown"
	}
	ua := strings.TrimSpace(r.Header.Get("User-Agent"))
	if ua == "" {
		ua = "unknown"
	}
	return fmt.Sprintf("%s-mcp-http-%s", g.agentID, stableSessionSuffix(remoteHost+"|"+ua))
}

func stableSessionSuffix(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:8])
}

func hostOnly(hostPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return ""
	}
	host := hostPort
	if strings.Contains(hostPort, ":") {
		if parsedHost, _, err := net.SplitHostPort(hostPort); err == nil {
			host = parsedHost
		}
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return strings.ToLower(host)
}
