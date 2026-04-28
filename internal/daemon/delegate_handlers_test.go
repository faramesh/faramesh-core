package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/delegate"
)

func newTestDaemon(t *testing.T) (*Daemon, *http.ServeMux) {
	t.Helper()
	d := &Daemon{
		delegate: delegate.NewService(
			delegate.NewMemoryStore(),
			delegate.DeriveKey([]byte("handler-test")),
			5,
			func() time.Time { return time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC) },
		),
	}
	mux := http.NewServeMux()
	d.registerDelegateRoutes(mux)
	return d, mux
}

func doJSON(t *testing.T, mux *http.ServeMux, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Result(), rec.Body.Bytes()
}

func TestHandleDelegateGrant_OK(t *testing.T) {
	_, mux := newTestDaemon(t)

	resp, body := doJSON(t, mux, "POST", "/api/v1/delegate/grant", map[string]string{
		"from_agent": "supervisor",
		"to_agent":   "worker",
		"scope":      "stripe/*",
		"ttl":        "1h",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	var got struct {
		Token     string `json:"token"`
		FromAgent string `json:"from_agent"`
		ToAgent   string `json:"to_agent"`
		Scope     string `json:"scope"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(got.Token, "del_") {
		t.Errorf("expected del_ token, got %s", got.Token)
	}
	if got.FromAgent != "supervisor" || got.ToAgent != "worker" {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestHandleDelegateGrant_BadRequest(t *testing.T) {
	_, mux := newTestDaemon(t)

	resp, _ := doJSON(t, mux, "POST", "/api/v1/delegate/grant", map[string]string{
		"from_agent": "",
		"to_agent":   "worker",
	})
	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for missing from_agent, got %d", resp.StatusCode)
	}
}

func TestHandleDelegateGrant_DepthExceeded(t *testing.T) {
	d := &Daemon{
		delegate: delegate.NewService(
			delegate.NewMemoryStore(),
			delegate.DeriveKey([]byte("k")),
			1, // only root grants allowed
			func() time.Time { return time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC) },
		),
	}
	mux := http.NewServeMux()
	d.registerDelegateRoutes(mux)

	if resp, _ := doJSON(t, mux, "POST", "/api/v1/delegate/grant", map[string]string{
		"from_agent": "a", "to_agent": "b", "ttl": "1h",
	}); resp.StatusCode != 200 {
		t.Fatalf("seed grant failed: %d", resp.StatusCode)
	}
	resp, _ := doJSON(t, mux, "POST", "/api/v1/delegate/grant", map[string]string{
		"from_agent": "b", "to_agent": "c", "ttl": "1h",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 on depth excess, got %d", resp.StatusCode)
	}
}

func TestHandleDelegateGrant_MethodNotAllowed(t *testing.T) {
	_, mux := newTestDaemon(t)
	resp, _ := doJSON(t, mux, "GET", "/api/v1/delegate/grant", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestHandleDelegateList_RequiresAgentID(t *testing.T) {
	_, mux := newTestDaemon(t)
	resp, _ := doJSON(t, mux, "GET", "/api/v1/delegate/list", nil)
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleDelegateLifecycle_GrantListVerifyRevokeInspect(t *testing.T) {
	_, mux := newTestDaemon(t)

	// Grant.
	resp, body := doJSON(t, mux, "POST", "/api/v1/delegate/grant", map[string]string{
		"from_agent": "a", "to_agent": "b", "scope": "*", "ttl": "1h",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("grant: %d body=%s", resp.StatusCode, body)
	}
	var grantResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &grantResp)

	// List.
	resp, body = doJSON(t, mux, "GET", "/api/v1/delegate/list?agent_id=a", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var listResp struct {
		Delegations []map[string]any `json:"delegations"`
	}
	_ = json.Unmarshal(body, &listResp)
	if len(listResp.Delegations) != 1 {
		t.Errorf("expected 1 delegation, got %d", len(listResp.Delegations))
	}

	// Verify (valid).
	resp, body = doJSON(t, mux, "POST", "/api/v1/delegate/verify", map[string]string{"token": grantResp.Token})
	if resp.StatusCode != 200 {
		t.Fatalf("verify: %d", resp.StatusCode)
	}
	var verifyResp struct {
		Valid bool `json:"valid"`
	}
	_ = json.Unmarshal(body, &verifyResp)
	if !verifyResp.Valid {
		t.Errorf("expected valid=true, got %s", body)
	}

	// Inspect.
	resp, body = doJSON(t, mux, "GET", "/api/v1/delegate/inspect?token="+grantResp.Token, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("inspect: %d body=%s", resp.StatusCode, body)
	}

	// Revoke.
	resp, body = doJSON(t, mux, "POST", "/api/v1/delegate/revoke", map[string]string{
		"from_agent": "a", "to_agent": "b",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: %d body=%s", resp.StatusCode, body)
	}
	var revResp struct {
		Revoked bool `json:"revoked"`
	}
	_ = json.Unmarshal(body, &revResp)
	if !revResp.Revoked {
		t.Errorf("expected revoked=true")
	}

	// Verify after revoke is invalid.
	resp, body = doJSON(t, mux, "POST", "/api/v1/delegate/verify", map[string]string{"token": grantResp.Token})
	_ = json.Unmarshal(body, &verifyResp)
	if verifyResp.Valid {
		t.Errorf("expected verify to fail after revoke")
	}
}

func TestHandleDelegateInspect_NotFound(t *testing.T) {
	_, mux := newTestDaemon(t)
	resp, _ := doJSON(t, mux, "GET", "/api/v1/delegate/inspect?token=del_does.notexist", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandleDelegateChain(t *testing.T) {
	_, mux := newTestDaemon(t)
	for _, fromTo := range [][2]string{{"a", "b"}, {"b", "c"}, {"c", "d"}} {
		resp, _ := doJSON(t, mux, "POST", "/api/v1/delegate/grant", map[string]string{
			"from_agent": fromTo[0], "to_agent": fromTo[1], "scope": "*", "ttl": "1h",
		})
		if resp.StatusCode != 200 {
			t.Fatalf("seed %v: %d", fromTo, resp.StatusCode)
		}
	}
	resp, body := doJSON(t, mux, "GET", "/api/v1/delegate/chain?agent_id=d", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("chain: %d", resp.StatusCode)
	}
	var chainResp struct {
		AgentID string           `json:"agent_id"`
		Chain   []map[string]any `json:"chain"`
	}
	_ = json.Unmarshal(body, &chainResp)
	if chainResp.AgentID != "d" {
		t.Errorf("agent_id=%s", chainResp.AgentID)
	}
	if len(chainResp.Chain) != 3 {
		t.Fatalf("expected 3 links, got %d (%s)", len(chainResp.Chain), body)
	}
	if chainResp.Chain[0]["from_agent"] != "a" {
		t.Errorf("expected root link from=a, got %v", chainResp.Chain[0])
	}
}

func TestHandleDelegate_ServiceNotInitialised(t *testing.T) {
	d := &Daemon{}
	mux := http.NewServeMux()
	d.registerDelegateRoutes(mux)
	resp, _ := doJSON(t, mux, "POST", "/api/v1/delegate/grant", map[string]string{
		"from_agent": "a", "to_agent": "b",
	})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}
