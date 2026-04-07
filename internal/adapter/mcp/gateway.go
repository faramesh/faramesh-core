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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
		isNotification := msg.ID == nil && msg.Method != ""
		if isNotification {
			if _, err := g.forwardToSubprocess(msg); err != nil {
				return nil, err
			}
			continue
		}
		outMsg, err := g.ProcessRequest(msg)
		if err != nil {
			return nil, err
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
}

// NewHTTPGateway creates an HTTP proxy gateway for MCP-over-HTTP servers.
func NewHTTPGateway(pipeline *core.Pipeline, agentID, targetURL string, log *zap.Logger) *HTTPGateway {
	g := &HTTPGateway{
		pipeline:  pipeline,
		agentID:   agentID,
		targetURL: targetURL,
		log:       log,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
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
	case http.MethodGet, http.MethodHead, http.MethodOptions:
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
	// Streamable HTTP: subscription and preflight without JSON-RPC body.
	if isStreamOrPreflightMethod(r.Method) {
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
		g.handleMCPBatch(w, r, body)
		return
	}

	g.handleMCPSingle(w, r, body)
}

func (g *HTTPGateway) handleMCPSingle(w http.ResponseWriter, r *http.Request, body []byte) {
	var msg MCPMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
		return
	}
	streamOut := acceptsEventStream(r)

	if msg.Method == "tools/call" {
		resp, forward, toolName, err := g.interceptToolsCall(msg)
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
			g.forwardMCPStream(w, r, body, toolName)
			return
		}
		g.forwardMCPWithPostScan(w, r, body, toolName)
		return
	}

	if streamOut {
		g.forwardMCPStream(w, r, body, "")
		return
	}
	g.forwardMCPRaw(w, r, body)
}

// handleMCPBatch processes JSON-RPC 2.0 batch requests in order. Each element is handled
// independently: tools/call messages are governed; other methods are forwarded upstream
// one request at a time. Notifications (no id) are forwarded but omitted from the batch
// response, per JSON-RPC semantics.
func (g *HTTPGateway) handleMCPBatch(w http.ResponseWriter, r *http.Request, body []byte) {
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
		isNotification := msg.ID == nil && msg.Method != ""
		if isNotification {
			if _, _, _, err := g.doUpstreamRequest(r, rawEl); err != nil {
				g.log.Error("upstream MCP server error", zap.Error(err))
				http.Error(w, `{"error":"upstream service unavailable"}`, http.StatusBadGateway)
				return
			}
			continue
		}
		if msg.Method == "tools/call" {
			resp, forward, toolName, err := g.interceptToolsCall(msg)
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
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	return resp.StatusCode, b, resp.Header, nil
}

// forwardMCPStream proxies upstream and copies the response without buffering the full body.
// When the client sends Accept: text/event-stream, streamable HTTP servers may return long-lived
// SSE responses; output post-scan (JSON tool results) is not applied on this path.
func (g *HTTPGateway) forwardMCPStream(w http.ResponseWriter, r *http.Request, body []byte, toolID string) {
	_ = toolID
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
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, g.upstreamURL(r), bytes.NewReader(body))
	if err != nil {
		g.log.Error("failed to build upstream request", zap.Error(err))
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	for k, vs := range r.Header {
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
		if err := g.streamSSEWithPostScan(w, resp.Body, toolID); err != nil {
			return
		}
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func (g *HTTPGateway) streamSSEWithPostScan(w http.ResponseWriter, body io.Reader, toolID string) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		out := transformSSEDataLineForPostScan(line, toolID, g.pipeline)
		if _, err := w.Write(out); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
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
func (g *HTTPGateway) interceptToolsCall(msg MCPMessage) (resp *MCPMessage, forward bool, toolName string, err error) {
	var params toolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, false, "", err
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
