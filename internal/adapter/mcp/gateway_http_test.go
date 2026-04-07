package mcp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const mcpTestPolicy = `
faramesh-version: "1.0"
agent-id: "mcp-http-test"
default_effect: deny
rules:
  - id: allow-safe
    match:
      tool: "safe/tool"
    effect: permit
    reason_code: RULE_PERMIT
`

func testMCPPipeline(t *testing.T) *core.Pipeline {
	t.Helper()
	return testMCPPipelineFromYAML(t, mcpTestPolicy)
}

func testMCPPipelineFromYAML(t *testing.T, yaml string) *core.Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	return core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func TestHTTPGateway_toolsCallDenied(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called on deny")
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger/x","arguments":{}}}`)))
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var msg MCPMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error == nil || msg.Error.Code != -32003 {
		t.Fatalf("expected deny error, got %+v", msg)
	}
}

func TestHTTPGateway_toolsCallPermitUpstream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m MCPMessage
		_ = json.Unmarshal(b, &m)
		resp := MCPMessage{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(`{"ok":true}`)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"safe/tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	var msg MCPMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
}

func TestHTTPGateway_initializeForwarded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var m MCPMessage
		if err := json.Unmarshal(b, &m); err != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		if m.Method != "initialize" {
			t.Errorf("expected initialize, got %q", m.Method)
		}
		resp := MCPMessage{
			JSONRPC: "2.0",
			ID:      m.ID,
			Result:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"upstream","version":"0.0.1"}}`),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"client"}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	var msg MCPMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}
	if !strings.Contains(string(msg.Result), "protocolVersion") {
		t.Fatalf("expected initialize result, got %s", msg.Result)
	}
}

func TestHTTPGateway_batchTwoDeniesNoUpstream(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	batch := `[
	  {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"other/x","arguments":{}}},
	  {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"y/z","arguments":{}}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(batch)))
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if calls != 0 {
		t.Fatalf("upstream called %d times", calls)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var out []MCPMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Error == nil || out[1].Error == nil {
		t.Fatalf("expected two errors: %+v", out)
	}
}

func TestHTTPGateway_GET_streamsSSE(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("upstream got method %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "data: {\"ok\":true}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("expected SSE payload in body: %q", rec.Body.String())
	}
}

func TestHTTPGateway_POST_SSE_toolsCallPostScanDeny(t *testing.T) {
	pol := `
faramesh-version: "1.0"
agent-id: "mcp-http-test"
default_effect: deny
post_rules:
  - id: deny-secret
    match:
      tool: "safe/tool"
    scan:
      - pattern: "SECRET"
        action: deny
        reason: "no secrets"
rules:
  - id: allow-safe
    match:
      tool: "safe/tool"
    effect: permit
`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		payload := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"SECRET"}]}}`
		_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipelineFromYAML(t, pol), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, `"error"`) || !strings.Contains(out, "Faramesh post-scan") {
		t.Fatalf("expected post-scan deny in SSE body: %q", out)
	}
}

func TestHTTPGateway_POST_SSE_toolsCallPostScanRedact(t *testing.T) {
	pol := `
faramesh-version: "1.0"
agent-id: "mcp-http-test"
default_effect: deny
post_rules:
  - id: redact-aaa
    match:
      tool: "safe/tool"
    scan:
      - pattern: "AAA"
        action: redact
        replacement: "[redacted]"
rules:
  - id: allow-safe
    match:
      tool: "safe/tool"
    effect: permit
`
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		payload := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"x AAA y"}]}}`
		_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipelineFromYAML(t, pol), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if strings.Contains(out, "AAA") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("expected redacted output in SSE body: %q", out)
	}
}

func TestHTTPGateway_POST_SSE_toolsCallPermitStreams(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("upstream method %s", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		var m MCPMessage
		if err := json.Unmarshal(b, &m); err != nil || m.Method != "tools/call" {
			t.Fatalf("unexpected body: %s", string(b))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"result"`) {
		t.Fatalf("expected streamed SSE body: %q", rec.Body.String())
	}
}

func TestHTTPGateway_POST_SSE_toolsCallDeniedNoUpstream(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"danger/x","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if calls != 0 {
		t.Fatalf("upstream called %d times", calls)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var msg MCPMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &msg); err != nil || msg.Error == nil {
		t.Fatalf("expected JSON-RPC error, got %+v", msg)
	}
}

func TestHTTPGateway_batchWithSSERejected(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(batch)))
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPGateway_OPTIONS_forwards(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions {
			t.Fatalf("upstream got method %s", r.Method)
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("expected CORS methods header from upstream")
	}
}

func TestHTTPGateway_DELETE_forwards(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("upstream got method %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestHTTPGateway_singleNotificationAccepted(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected one upstream call, got %d", calls)
	}
	if strings.TrimSpace(rec.Body.String()) != "" {
		t.Fatalf("expected empty body, got %q", rec.Body.String())
	}
}

func TestHTTPGateway_singleResponseAccepted(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":"srv-req-1","result":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected one upstream call, got %d", calls)
	}
}

func TestHTTPGateway_batchNotificationsAcceptedNoBody(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `[
	  {"jsonrpc":"2.0","method":"notifications/initialized","params":{}},
	  {"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"123"}}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", rec.Code, rec.Body.String())
	}
	if calls != 2 {
		t.Fatalf("expected two upstream calls, got %d", calls)
	}
	if strings.TrimSpace(rec.Body.String()) != "" {
		t.Fatalf("expected empty body, got %q", rec.Body.String())
	}
}

func TestHTTPGateway_blocksDisallowedOrigin(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be reached for blocked origins")
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTPGateway_allowsConfiguredOrigin(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), "https://app.example.com")
	body := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHTTPGateway_sessionIsolationUsesMcpSessionHeader(t *testing.T) {
	pol := `
faramesh-version: "1.0"
agent-id: "mcp-http-test"
default_effect: deny
rules:
  - id: deny-repeat-safe
    match:
      tool: "safe/tool"
      when: "history_contains_within('safe/tool', 300)"
    effect: deny
    reason_code: REPEAT_BLOCK
  - id: allow-safe
    match:
      tool: "safe/tool"
    effect: permit
`

	upCalls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upCalls++
		b, _ := io.ReadAll(r.Body)
		var m MCPMessage
		_ = json.Unmarshal(b, &m)
		resp := MCPMessage{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(`{"ok":true}`)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer up.Close()

	g := NewHTTPGateway(testMCPPipelineFromYAML(t, pol), "agent-1", up.URL, zap.NewNop())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}`

	reqA := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	reqA.Header.Set("Mcp-Session-Id", "session-A")
	recA := httptest.NewRecorder()
	g.handleMCP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("first session code=%d body=%s", recA.Code, recA.Body.String())
	}

	reqB := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	reqB.Header.Set("Mcp-Session-Id", "session-B")
	recB := httptest.NewRecorder()
	g.handleMCP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("second session code=%d body=%s", recB.Code, recB.Body.String())
	}

	if upCalls != 2 {
		t.Fatalf("expected both requests to reach upstream, calls=%d", upCalls)
	}
}

func TestHTTPGateway_edgeAuthBearerRequired(t *testing.T) {
	upCalls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()

	g := NewHTTPGatewayWithConfig(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), HTTPGatewayConfig{
		EdgeAuthMode:        "bearer",
		EdgeAuthBearerToken: "topsecret",
	})
	body := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`

	reqNoAuth := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	recNoAuth := httptest.NewRecorder()
	g.handleMCP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%q", recNoAuth.Code, recNoAuth.Body.String())
	}

	reqAuth := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	reqAuth.Header.Set("Authorization", "Bearer topsecret")
	recAuth := httptest.NewRecorder()
	g.handleMCP(recAuth, reqAuth)
	if recAuth.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", recAuth.Code, recAuth.Body.String())
	}

	if upCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upCalls)
	}
}

func TestHTTPGateway_edgeAuthMTLSRequired(t *testing.T) {
	upCalls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()

	g := NewHTTPGatewayWithConfig(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), HTTPGatewayConfig{
		EdgeAuthMode: "mtls",
	})
	body := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`

	reqNoTLS := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	recNoTLS := httptest.NewRecorder()
	g.handleMCP(recNoTLS, reqNoTLS)
	if recNoTLS.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%q", recNoTLS.Code, recNoTLS.Body.String())
	}

	reqTLS := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	reqTLS.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	recTLS := httptest.NewRecorder()
	g.handleMCP(recTLS, reqTLS)
	if recTLS.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%q", recTLS.Code, recTLS.Body.String())
	}

	if upCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upCalls)
	}
}

func TestHTTPGateway_protocolVersionStrictRejectsMissingRequestHeader(t *testing.T) {
	upCalls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upCalls++
		w.Header().Set("MCP-Protocol-Version", "2025-06-18")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer up.Close()

	g := NewHTTPGatewayWithConfig(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), HTTPGatewayConfig{
		ProtocolVersionMode: "strict",
		ProtocolVersion:     "2025-06-18",
	})
	body := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%q", rec.Code, rec.Body.String())
	}
	if upCalls != 0 {
		t.Fatalf("expected no upstream calls, got %d", upCalls)
	}
}

func TestHTTPGateway_protocolVersionStrictRejectsMissingUpstreamHeader(t *testing.T) {
	upCalls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upCalls++
		resp := MCPMessage{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{"ok":true}`)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer up.Close()

	g := NewHTTPGatewayWithConfig(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), HTTPGatewayConfig{
		ProtocolVersionMode: "strict",
		ProtocolVersion:     "2025-06-18",
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.handleMCP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d body=%q", rec.Code, rec.Body.String())
	}
	if upCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upCalls)
	}
}

func TestHTTPGateway_sessionTTLExpires(t *testing.T) {
	upCalls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upCalls++
		b, _ := io.ReadAll(r.Body)
		var m MCPMessage
		_ = json.Unmarshal(b, &m)
		resp := MCPMessage{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(`{"ok":true}`)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer up.Close()

	g := NewHTTPGatewayWithConfig(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), HTTPGatewayConfig{
		SessionTTL: 5 * time.Minute,
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}`

	req1 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req1.Header.Set("Mcp-Session-Id", "session-expire")
	rec1 := httptest.NewRecorder()
	g.handleMCP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d body=%q", rec1.Code, rec1.Body.String())
	}

	probe := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	probe.Header.Set("Mcp-Session-Id", "session-expire")
	sessionID := g.sessionIDForRequest(probe)
	g.sessionMu.Lock()
	state := g.sessionStates[sessionID]
	state.createdAt = time.Now().Add(-10 * time.Minute)
	g.sessionStates[sessionID] = state
	g.sessionMu.Unlock()

	req2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req2.Header.Set("Mcp-Session-Id", "session-expire")
	rec2 := httptest.NewRecorder()
	g.handleMCP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session, got %d body=%q", rec2.Code, rec2.Body.String())
	}
	if upCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upCalls)
	}
}

func TestHTTPGateway_deleteTerminatesSessionState(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			var m MCPMessage
			_ = json.Unmarshal(b, &m)
			resp := MCPMessage{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(`{"ok":true}`)}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer up.Close()

	g := NewHTTPGatewayWithConfig(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), HTTPGatewayConfig{
		SessionTTL: 10 * time.Minute,
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe/tool","arguments":{}}}`

	req1 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req1.Header.Set("Mcp-Session-Id", "session-delete")
	rec1 := httptest.NewRecorder()
	g.handleMCP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec1.Code, rec1.Body.String())
	}

	probe := httptest.NewRequest(http.MethodPost, "/", nil)
	probe.Header.Set("Mcp-Session-Id", "session-delete")
	sessionID := g.sessionIDForRequest(probe)
	g.sessionMu.Lock()
	_, existsBefore := g.sessionStates[sessionID]
	g.sessionMu.Unlock()
	if !existsBefore {
		t.Fatal("expected gateway session state to exist")
	}

	reqDelete := httptest.NewRequest(http.MethodDelete, "/", nil)
	reqDelete.Header.Set("Mcp-Session-Id", "session-delete")
	recDelete := httptest.NewRecorder()
	g.handleMCP(recDelete, reqDelete)
	if recDelete.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%q", recDelete.Code, recDelete.Body.String())
	}

	g.sessionMu.Lock()
	_, existsAfter := g.sessionStates[sessionID]
	g.sessionMu.Unlock()
	if existsAfter {
		t.Fatal("expected gateway session state to be removed after DELETE")
	}
}

func TestHTTPGateway_SSEReplayLastEventID(t *testing.T) {
	call := 0
	seenLastEventID := make([]string, 0, 2)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		seenLastEventID = append(seenLastEventID, strings.TrimSpace(r.Header.Get("Last-Event-ID")))
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		switch call {
		case 1:
			_, _ = fmt.Fprintf(w, "id: evt-1\n")
			_, _ = fmt.Fprintf(w, "data: first\n\n")
			_, _ = fmt.Fprintf(w, "id: evt-2\n")
			_, _ = fmt.Fprintf(w, "data: second\n\n")
		case 2:
			_, _ = fmt.Fprintf(w, "id: evt-3\n")
			_, _ = fmt.Fprintf(w, "data: third\n\n")
		default:
			t.Fatalf("unexpected upstream call %d", call)
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer up.Close()

	g := NewHTTPGatewayWithConfig(testMCPPipeline(t), "agent-1", up.URL, zap.NewNop(), HTTPGatewayConfig{
		SSEReplayEnabled:   true,
		SSEReplayMaxEvents: 32,
		SSEReplayMaxAge:    time.Hour,
	})

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Accept", "text/event-stream")
	req1.Header.Set("Mcp-Session-Id", "session-replay")
	rec1 := httptest.NewRecorder()
	g.handleMCP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request code=%d body=%q", rec1.Code, rec1.Body.String())
	}
	body1 := rec1.Body.String()
	if !strings.Contains(body1, "id: evt-1") || !strings.Contains(body1, "id: evt-2") {
		t.Fatalf("expected first stream events, got %q", body1)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Accept", "text/event-stream")
	req2.Header.Set("Mcp-Session-Id", "session-replay")
	req2.Header.Set("Last-Event-ID", "evt-1")
	rec2 := httptest.NewRecorder()
	g.handleMCP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second request code=%d body=%q", rec2.Code, rec2.Body.String())
	}
	body2 := rec2.Body.String()
	if strings.Contains(body2, "id: evt-1") {
		t.Fatalf("expected replay to start after evt-1, got %q", body2)
	}
	if !strings.Contains(body2, "id: evt-2") || !strings.Contains(body2, "id: evt-3") {
		t.Fatalf("expected replay + live events, got %q", body2)
	}
	if len(seenLastEventID) != 2 {
		t.Fatalf("expected 2 upstream calls, saw %d", len(seenLastEventID))
	}
	if seenLastEventID[0] != "" {
		t.Fatalf("first upstream request should not include Last-Event-ID, got %q", seenLastEventID[0])
	}
	if seenLastEventID[1] != "" {
		t.Fatalf("second upstream request should have gateway-consumed Last-Event-ID, got %q", seenLastEventID[1])
	}
}
