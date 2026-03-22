package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core"
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
