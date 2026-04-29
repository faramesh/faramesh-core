package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
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

func TestServerAuthorizeBurstRateLimitedBySourceIP(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())

	rateLimited := 0
	processed := 0

	for i := 0; i < 220; i++ {
		body := map[string]any{
			"agent_id": "burst-agent",
			"tool_id":  "http/get",
			"call_id":  fmt.Sprintf("call-burst-%d", i),
			"args":     map[string]any{"n": i},
		}
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.10:4000"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)

		switch rec.Code {
		case http.StatusOK:
			var resp authorizeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode authorize response: %v", err)
			}
			if resp.Effect == "" {
				t.Fatalf("missing effect in authorize response: %s", rec.Body.String())
			}
			processed++
		case http.StatusTooManyRequests:
			var payload map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode rate-limit payload: %v", err)
			}
			if got := payload["error"]; got != "rate_limited" {
				t.Fatalf("rate-limit payload error=%v want rate_limited", got)
			}
			if got := payload["reason_code"]; got != reasons.SessionRollingLimit {
				t.Fatalf("rate-limit reason_code=%v want %s", got, reasons.SessionRollingLimit)
			}
			rateLimited++
		default:
			t.Fatalf("unexpected status %d body=%s", rec.Code, rec.Body.String())
		}
	}

	if processed == 0 {
		t.Fatalf("expected at least one successful authorize response before saturation")
	}
	if rateLimited == 0 {
		t.Fatalf("expected burst to trigger HTTP 429 rate_limited responses")
	}
}

func TestServerAuthorizeRateLimitIsolatedBySourceIP(t *testing.T) {
	s := NewServer(testPipeline(t), zap.NewNop())

	saturates := false
	for i := 0; i < 240; i++ {
		body := map[string]any{
			"agent_id": "agent-a",
			"tool_id":  "http/get",
			"call_id":  fmt.Sprintf("call-a-%d", i),
			"args":     map[string]any{"n": i},
		}
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.11:4100"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)

		if rec.Code == http.StatusTooManyRequests {
			saturates = true
			break
		}
	}
	if !saturates {
		t.Fatalf("expected source IP 198.51.100.11 to hit burst limiter")
	}

	// Different source identity (IP) should use a distinct limiter bucket.
	body := map[string]any{
		"agent_id": "agent-b",
		"tool_id":  "http/get",
		"call_id":  "call-b",
		"args":     map[string]any{"q": "fresh source"},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.12:4200"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("unexpected cross-source throttling: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for fresh source identity, got %d body=%s", rec.Code, rec.Body.String())
	}
}
