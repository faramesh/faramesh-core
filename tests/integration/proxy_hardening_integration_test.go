package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/faramesh/faramesh-core/internal/adapter/proxy"
	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/credential"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

type integrationBroker struct {
	token string
}

func (b *integrationBroker) Name() string { return "integration-broker" }
func (b *integrationBroker) Fetch(_ context.Context, _ credential.FetchRequest) (*credential.Credential, error) {
	return &credential.Credential{Value: b.token, Source: b.Name(), Scope: "integration"}, nil
}
func (b *integrationBroker) Revoke(_ context.Context, _ *credential.Credential) error { return nil }

func buildPipelineFromPolicy(t *testing.T, raw string) *core.Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(raw))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func buildPipelineWithBroker(t *testing.T, broker credential.Broker) *core.Pipeline {
	t.Helper()
	policyDoc := `
faramesh-version: "1.0"
agent-id: "integration-broker-agent"
default_effect: deny
rules:
  - id: allow-http-forward
    match:
      tool: "proxy/http"
    effect: permit
`
	doc, ver, err := policy.LoadBytes([]byte(policyDoc))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	router := credential.NewRouter([]credential.Broker{broker}, broker)
	if err := router.AddRoute("proxy/http", broker.Name()); err != nil {
		t.Fatalf("add broker route: %v", err)
	}
	return core.NewPipeline(core.Config{
		Engine:           policy.NewAtomicEngine(eng),
		Sessions:         session.NewManager(),
		Defers:           deferwork.NewWorkflow(""),
		CredentialRouter: router,
	})
}

func newProxyClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
}

func TestHTTPForwardAuditVsEnforceParityIntegration(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)

	denyPolicy := `
faramesh-version: "1.0"
agent-id: "integration-audit-enforce"
default_effect: deny
rules:
  - id: block-http-forward
    match:
      tool: "proxy/http"
    effect: deny
    reason_code: RULE_DENY
`

	auditSrv := proxy.NewServer(
		buildPipelineFromPolicy(t, denyPolicy),
		zap.NewNop(),
		proxy.WithHTTPForwardProxy(true),
		proxy.WithNetworkHardeningMode("audit"),
		proxy.WithAllowedPrivateCIDRs([]string{"127.0.0.0/8"}),
	)
	auditClient := newProxyClient(t, auditSrv.Handler())
	auditReq, err := http.NewRequest(http.MethodGet, up.URL+"/audit", nil)
	if err != nil {
		t.Fatal(err)
	}
	auditResp, err := auditClient.Do(auditReq)
	if err != nil {
		t.Fatal(err)
	}
	defer auditResp.Body.Close()
	if auditResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(auditResp.Body)
		t.Fatalf("expected audit mode to permit via bypass, got %d body=%q", auditResp.StatusCode, body)
	}

	enforceSrv := proxy.NewServer(
		buildPipelineFromPolicy(t, denyPolicy),
		zap.NewNop(),
		proxy.WithHTTPForwardProxy(true),
		proxy.WithNetworkHardeningMode("enforce"),
		proxy.WithAllowedPrivateCIDRs([]string{"127.0.0.0/8"}),
	)
	enforceClient := newProxyClient(t, enforceSrv.Handler())
	enforceReq, err := http.NewRequest(http.MethodGet, up.URL+"/enforce", nil)
	if err != nil {
		t.Fatal(err)
	}
	enforceResp, err := enforceClient.Do(enforceReq)
	if err != nil {
		t.Fatal(err)
	}
	defer enforceResp.Body.Close()
	if enforceResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(enforceResp.Body)
		t.Fatalf("expected enforce mode deny, got %d body=%q", enforceResp.StatusCode, body)
	}
}

func TestInferenceRouteBrokerInjectionIntegration(t *testing.T) {
	type capture struct {
		Authorization string
	}
	captured := make(chan capture, 1)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- capture{Authorization: r.Header.Get("Authorization")}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)

	broker := &integrationBroker{token: "integration-token"}
	srv := proxy.NewServer(
		buildPipelineWithBroker(t, broker),
		zap.NewNop(),
		proxy.WithHTTPForwardProxy(true),
		proxy.WithInferenceRoutes([]proxy.InferenceRoute{
			{
				Name:                "broker-route",
				HostPattern:         "inference.local",
				PathPattern:         "/v1/*/*",
				Methods:             []string{"POST"},
				Upstream:            up.URL,
				AuthType:            "bearer",
				AuthBrokerRequired:  true,
				AuthBrokerToolID:    "proxy/http",
				AuthBrokerOperation: "invoke",
				AuthBrokerScope:     "inference:chat",
			},
		}),
	)

	client := newProxyClient(t, srv.Handler())
	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%q", resp.StatusCode, body)
	}

	select {
	case got := <-captured:
		if got.Authorization != "Bearer integration-token" {
			t.Fatalf("expected broker token injection, got %q", got.Authorization)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream capture")
	}
}

func TestHTTPForwardEmitsPinnedResolvedIPIntegration(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)

	obsCore, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(obsCore)

	permitPolicy := `
faramesh-version: "1.0"
agent-id: "integration-resolve"
default_effect: deny
rules:
  - id: allow-http-forward
    match:
      tool: "proxy/http"
    effect: permit
`

	srv := proxy.NewServer(
		buildPipelineFromPolicy(t, permitPolicy),
		logger,
		proxy.WithHTTPForwardProxy(true),
		proxy.WithNetworkHardeningMode("audit"),
	)

	client := newProxyClient(t, srv.Handler())
	req, err := http.NewRequest(http.MethodGet, up.URL+"/resolved", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%q", resp.StatusCode, body)
	}

	entries := logs.FilterMessage("proxy http forward").All()
	if len(entries) == 0 {
		t.Fatal("expected proxy http forward governance log")
	}
	ctx := entries[len(entries)-1].ContextMap()
	resolved := ""
	if v, ok := ctx["resolved_ip"].(string); ok {
		resolved = v
	}
	if resolved == "" {
		t.Fatal("expected non-empty resolved_ip in governance log")
	}
	if net.ParseIP(resolved) == nil {
		t.Fatalf("expected resolved_ip to be an IP literal, got %q", resolved)
	}
}

func TestLinuxIdentityBindingIntegrationSmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only integration test")
	}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)

	permitPolicy := `
faramesh-version: "1.0"
agent-id: "integration-linux-identity"
default_effect: deny
rules:
  - id: allow-http-forward
    match:
      tool: "proxy/http"
    effect: permit
`

	srv := proxy.NewServer(
		buildPipelineFromPolicy(t, permitPolicy),
		zap.NewNop(),
		proxy.WithHTTPForwardProxy(true),
		proxy.WithNetworkHardeningMode("enforce"),
		proxy.WithAllowedPrivateCIDRs([]string{"127.0.0.0/8"}),
	)

	client := newProxyClient(t, srv.Handler())
	req, err := http.NewRequest(http.MethodGet, up.URL+"/linux-identity", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		var payload map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		if payload["reason_code"] == reasons.NetworkIdentityUnresolved {
			t.Skip("linux identity binding not resolvable in this runtime environment")
		}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 or skip on identity unresolved, got %d body=%q", resp.StatusCode, body)
	}
}
