package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const testPolicyProxy = `
faramesh-version: "1.0"
agent-id: "proxy-test"
default_effect: deny
rules:
  - id: allow-http
    match:
      tool: "http/get"
    effect: permit
    reason_code: RULE_PERMIT
`

func testPipeline(t *testing.T) *core.Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(testPolicyProxy))
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

func TestServer_healthz(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestServer_authorize_permit(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())
	body := map[string]any{
		"agent_id": "a1",
		"tool_id":  "http/get",
		"args":     map[string]any{},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var resp authorizeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Effect != "PERMIT" {
		t.Fatalf("effect %q", resp.Effect)
	}
	if got := rec.Header().Get("X-Faramesh-Effect"); got != "PERMIT" {
		t.Fatalf("X-Faramesh-Effect = %q", got)
	}
}

func TestServer_authorize_deny(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())
	body := map[string]any{
		"agent_id": "a1",
		"tool_id":  "http/delete",
		"args":     map[string]any{},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp authorizeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Effect != "DENY" {
		t.Fatalf("effect %q want DENY", resp.Effect)
	}
}

func TestServer_authorize_agentFromHeader(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())
	body := map[string]any{
		"tool_id": "http/get",
		"args":    map[string]any{},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Faramesh-Agent-Id", "hdr-agent")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var resp authorizeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Effect != "PERMIT" {
		t.Fatalf("effect %q", resp.Effect)
	}
}

func TestServer_authorize_missingAgent(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())
	raw := []byte(`{"tool_id":"http/get"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d body %s", rec.Code, rec.Body.String())
	}
}

func TestServer_authorize_methodNotAllowed(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/v1/authorize", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestServer_scanOutput(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())
	body := map[string]any{"tool_id": "http/get", "output": "hello world"}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/scan_output", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
}
