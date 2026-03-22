package serverless

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

const testPol = `
faramesh-version: "1.0"
agent-id: "srv-test"
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
	doc, ver, err := policy.LoadBytes([]byte(testPol))
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

func TestAuthorizeHandler_permit(t *testing.T) {
	h := NewAuthorizeHandler(testPipeline(t), zap.NewNop())
	body := map[string]any{
		"agent_id": "a1",
		"tool_id":  "http/get",
		"args":     map[string]any{},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
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

func TestAuthorizeHandler_methodNotAllowed(t *testing.T) {
	h := NewAuthorizeHandler(testPipeline(t), zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/v1/authorize", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	HealthHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestAuthorizeHandler_missingAgent(t *testing.T) {
	h := NewAuthorizeHandler(testPipeline(t), zap.NewNop())
	raw := []byte(`{"tool_id":"http/get"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}
