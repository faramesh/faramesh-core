package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/credential"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

type testCredentialBroker struct {
	name     string
	token    string
	fetchErr error
	calls    atomic.Int32
}

func (b *testCredentialBroker) Name() string {
	if b == nil || b.name == "" {
		return "test-broker"
	}
	return b.name
}

func (b *testCredentialBroker) Fetch(_ context.Context, req credential.FetchRequest) (*credential.Credential, error) {
	b.calls.Add(1)
	if b.fetchErr != nil {
		return nil, b.fetchErr
	}
	return &credential.Credential{
		Value:  b.token,
		Source: b.Name(),
		Scope:  req.Scope,
	}, nil
}

func (b *testCredentialBroker) Revoke(_ context.Context, _ *credential.Credential) error {
	return nil
}

const policyHTTPForwardPermit = `
faramesh-version: "1.0"
agent-id: "proxy-http-test"
default_effect: deny
rules:
  - id: allow-http-forward
    match:
      tool: "proxy/http"
    effect: permit
`

func pipelineHTTPForwardPermit(t *testing.T) *core.Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(policyHTTPForwardPermit))
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

func pipelineHTTPForwardPermitWithBroker(t *testing.T, broker credential.Broker) *core.Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(policyHTTPForwardPermit))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
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

func TestHTTPForwardProxyPermitted(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(up.Close)

	srv := NewServer(pipelineHTTPForwardPermit(t), zap.NewNop(), WithHTTPForwardProxy(true))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(up.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream-ok" {
		t.Fatalf("body %q", body)
	}
}

func TestHTTPForwardProxyDeniedByPolicy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should-not-see")
	}))
	t.Cleanup(up.Close)

	srv := NewServer(testPipeline(t), zap.NewNop(), WithHTTPForwardProxy(true))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(up.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "http forward denied" {
		t.Fatalf("expected denied: %+v", m)
	}
}

func TestHTTPForwardNotEnabledFallsThroughToMux(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct")
	}))
	t.Cleanup(up.Close)

	// CONNECT only — absolute-form proxy requests must not be forwarded.
	srv := NewServer(pipelineHTTPForwardPermit(t), zap.NewNop(), WithConnectProxy(true))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(up.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, _ := io.ReadAll(resp.Body)
	if string(body) == "direct" {
		t.Fatalf("request reached upstream but HTTP forward was disabled on this listener")
	}
}

func TestHTTPForwardHardeningEnforceBlocksInternalTargets(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream")
	}))
	t.Cleanup(up.Close)

	srv := NewServer(
		pipelineHTTPForwardPermit(t),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithNetworkHardeningMode("enforce"),
	)
	srv.procResolver = testProcessResolver{id: &ProcessIdentity{PID: 123, Executable: "/bin/test"}}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(up.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if payload["reason_code"] != reasons.NetworkSSRFBlock {
		t.Fatalf("expected reason_code=%s, got %+v", reasons.NetworkSSRFBlock, payload)
	}
}

func TestHTTPForwardInferenceRouteRewritesUpstreamAuthAndModel(t *testing.T) {
	type capture struct {
		Path          string
		Query         string
		Authorization string
		RouteHeader   string
		Body          []byte
	}
	captured := make(chan capture, 1)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- capture{
			Path:          r.URL.Path,
			Query:         r.URL.RawQuery,
			Authorization: r.Header.Get("Authorization"),
			RouteHeader:   r.Header.Get("X-Route"),
			Body:          body,
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)

	routes := []InferenceRoute{
		{
			Name:         "openai-route",
			HostPattern:  "inference.local",
			PathPattern:  "/v1/*/*",
			Methods:      []string{"POST"},
			Upstream:     up.URL + "/routed",
			AuthType:     "bearer",
			AuthToken:    "secret-token",
			ForceHeaders: map[string]string{"X-Route": "active"},
			ModelRewrite: "gpt-4o-mini",
		},
	}

	srv := NewServer(
		pipelineHTTPForwardPermit(t),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithInferenceRoutes(routes),
	)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	reqBody := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`)
	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions?tenant=prod", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%q", resp.StatusCode, body)
	}

	select {
	case got := <-captured:
		if got.Path != "/routed/v1/chat/completions" {
			t.Fatalf("unexpected routed path: %q", got.Path)
		}
		if got.Query != "tenant=prod" {
			t.Fatalf("unexpected routed query: %q", got.Query)
		}
		if got.Authorization != "Bearer secret-token" {
			t.Fatalf("unexpected authorization header: %q", got.Authorization)
		}
		if got.RouteHeader != "active" {
			t.Fatalf("unexpected force header value: %q", got.RouteHeader)
		}

		var payload map[string]any
		if err := json.Unmarshal(got.Body, &payload); err != nil {
			t.Fatalf("decode rewritten body: %v body=%q", err, got.Body)
		}
		if payload["model"] != "gpt-4o-mini" {
			t.Fatalf("expected rewritten model gpt-4o-mini, got %v", payload["model"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for routed upstream request")
	}
}

func TestHTTPForwardInferenceRouteModelRewriteEmitsReasonCode(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)

	routes := []InferenceRoute{
		{
			Name:         "rewrite-route",
			HostPattern:  "inference.local",
			PathPattern:  "/v1/*/*",
			Methods:      []string{"POST"},
			Upstream:     up.URL + "/routed",
			AuthType:     "none",
			ModelRewrite: "gpt-4o-mini",
		},
	}

	coreObs, observedLogs := observer.New(zapcore.InfoLevel)
	logger := zap.New(coreObs)

	srv := NewServer(
		pipelineHTTPForwardPermit(t),
		logger,
		WithHTTPForwardProxy(true),
		WithAllowedPrivateCIDRs([]string{"127.0.0.0/8"}),
		WithInferenceRoutes(routes),
	)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%q", resp.StatusCode, body)
	}

	entries := observedLogs.FilterMessage("proxy inference model rewrite applied").All()
	if len(entries) == 0 {
		t.Fatal("expected model rewrite governance log entry")
	}
	if got := entries[0].ContextMap()["reason_code"]; got != reasons.InferenceModelRewriteApplied {
		t.Fatalf("expected reason_code=%s, got %v", reasons.InferenceModelRewriteApplied, got)
	}
}

func TestHTTPForwardInferenceRouteMissingInEnforceModeDenied(t *testing.T) {
	srv := NewServer(
		pipelineHTTPForwardPermit(t),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithNetworkHardeningMode("enforce"),
	)
	srv.procResolver = testProcessResolver{id: &ProcessIdentity{PID: 123, Executable: "/bin/test"}}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode deny payload: %v", err)
	}
	if payload["reason_code"] != reasons.InferenceRouteNotFound {
		t.Fatalf("expected reason_code=%s, got %+v", reasons.InferenceRouteNotFound, payload)
	}
}

func TestHTTPForwardHardeningAuditAllowsPolicyDeniedTraffic(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "audit-upstream-ok")
	}))
	t.Cleanup(up.Close)

	srv := NewServer(
		testPipeline(t),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithNetworkHardeningMode("audit"),
	)
	srv.procResolver = testProcessResolver{id: &ProcessIdentity{PID: 123, Executable: "/bin/test"}}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(up.URL + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 in audit mode, got %d body=%q", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "audit-upstream-ok" {
		t.Fatalf("unexpected upstream body: %q", body)
	}
}

func TestHTTPForwardRejectsTooLargeRequestBody(t *testing.T) {
	var upstreamHits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "should-not-hit")
	}))
	t.Cleanup(up.Close)

	srv := NewServer(pipelineHTTPForwardPermit(t), zap.NewNop(), WithHTTPForwardProxy(true))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	oversized := bytes.Repeat([]byte("a"), (16<<20)+1)
	req, err := http.NewRequest(http.MethodPost, up.URL+"/upload", bytes.NewReader(oversized))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 413, got %d body=%q", resp.StatusCode, body)
	}
	if upstreamHits.Load() != 0 {
		t.Fatalf("expected upstream to not receive oversized request, hits=%d", upstreamHits.Load())
	}
}

func TestStripHopByHopDropsConnectionTokenHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("Connection", "X-Internal-Hop, X-Second-Hop")
	src.Set("X-Internal-Hop", "secret")
	src.Set("X-Second-Hop", "transient")
	src.Set("X-Forwarded-For", "203.0.113.10")

	dst := http.Header{}
	stripHopByHop(dst, src)

	if got := dst.Get("X-Internal-Hop"); got != "" {
		t.Fatalf("expected X-Internal-Hop to be stripped, got %q", got)
	}
	if got := dst.Get("X-Second-Hop"); got != "" {
		t.Fatalf("expected X-Second-Hop to be stripped, got %q", got)
	}
	if got := dst.Get("X-Forwarded-For"); got == "" {
		t.Fatalf("expected non hop-by-hop header to be retained")
	}
}

func TestHTTPForwardInferenceRouteUnsafeAuthHeaderDeniedInEnforceMode(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should-not-hit")
	}))
	t.Cleanup(up.Close)

	routes := []InferenceRoute{
		{
			Name:         "bad-auth-header-route",
			HostPattern:  "inference.local",
			PathPattern:  "/v1/*/*",
			Methods:      []string{"POST"},
			Upstream:     up.URL + "/routed",
			AuthType:     "header",
			AuthHeader:   "Connection",
			AuthToken:    "token",
			ModelRewrite: "gpt-4o-mini",
		},
	}

	srv := NewServer(
		pipelineHTTPForwardPermit(t),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithNetworkHardeningMode("enforce"),
		WithAllowedPrivateCIDRs([]string{"127.0.0.0/8"}),
		WithInferenceRoutes(routes),
	)
	srv.procResolver = testProcessResolver{id: &ProcessIdentity{PID: 123, Executable: "/bin/test"}}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d body=%q", resp.StatusCode, body)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode deny payload: %v", err)
	}
	if payload["reason_code"] != reasons.InferenceAuthInjectionFailed {
		t.Fatalf("expected reason_code=%s, got %+v", reasons.InferenceAuthInjectionFailed, payload)
	}
}

func TestHTTPForwardInferenceRouteEnforceBlocksPrivateRouteUpstream(t *testing.T) {
	routes := []InferenceRoute{
		{
			Name:        "private-upstream",
			HostPattern: "inference.local",
			PathPattern: "/v1/*/*",
			Methods:     []string{"POST"},
			Upstream:    "http://127.0.0.1:18080",
			AuthType:    "none",
		},
	}

	srv := NewServer(
		pipelineHTTPForwardPermit(t),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithNetworkHardeningMode("enforce"),
		WithInferenceRoutes(routes),
	)
	srv.procResolver = testProcessResolver{id: &ProcessIdentity{PID: 123, Executable: "/bin/test"}}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d body=%q", resp.StatusCode, body)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode deny payload: %v", err)
	}
	if payload["reason_code"] != reasons.NetworkSSRFBlock {
		t.Fatalf("expected reason_code=%s, got %+v", reasons.NetworkSSRFBlock, payload)
	}
}

func TestHTTPForwardHardeningAllowsConfiguredPrivateCIDR(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "private-ok")
	}))
	t.Cleanup(up.Close)

	srv := NewServer(
		pipelineHTTPForwardPermit(t),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithNetworkHardeningMode("enforce"),
		WithAllowedPrivateCIDRs([]string{"127.0.0.0/8"}),
	)
	srv.procResolver = testProcessResolver{id: &ProcessIdentity{PID: 123, Executable: "/bin/test"}}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodGet, up.URL+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%q", resp.StatusCode, body)
	}
}

func TestHTTPForwardInferenceRouteUsesCredentialBrokerToken(t *testing.T) {
	type capture struct {
		Authorization string
		Body          []byte
	}
	captured := make(chan capture, 1)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured <- capture{Authorization: r.Header.Get("Authorization"), Body: body}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)

	broker := &testCredentialBroker{name: "fake-broker", token: "broker-token"}
	routes := []InferenceRoute{
		{
			Name:                "broker-route",
			HostPattern:         "inference.local",
			PathPattern:         "/v1/*/*",
			Methods:             []string{"POST"},
			Upstream:            up.URL + "/routed",
			AuthType:            "bearer",
			AuthBrokerRequired:  true,
			AuthBrokerToolID:    "proxy/http",
			AuthBrokerOperation: "invoke",
			AuthBrokerScope:     "inference:chat",
		},
	}

	srv := NewServer(
		pipelineHTTPForwardPermitWithBroker(t, broker),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithInferenceRoutes(routes),
	)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%q", resp.StatusCode, body)
	}

	select {
	case got := <-captured:
		if got.Authorization != "Bearer broker-token" {
			t.Fatalf("expected broker auth token, got %q", got.Authorization)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for broker-routed upstream request")
	}

	if broker.calls.Load() != 1 {
		t.Fatalf("expected exactly one broker fetch call, got %d", broker.calls.Load())
	}
}

func TestHTTPForwardInferenceRouteBrokerRequiredFailsClosedWhenBrokerUnavailable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should-not-hit")
	}))
	t.Cleanup(up.Close)

	brokenBroker := &testCredentialBroker{name: "fake-broker", fetchErr: errors.New("backend unavailable")}
	routes := []InferenceRoute{
		{
			Name:                "broker-required-route",
			HostPattern:         "inference.local",
			PathPattern:         "/v1/*/*",
			Methods:             []string{"POST"},
			Upstream:            up.URL + "/routed",
			AuthType:            "bearer",
			AuthBrokerRequired:  true,
			AuthBrokerToolID:    "proxy/http",
			AuthBrokerOperation: "invoke",
			AuthBrokerScope:     "inference:chat",
		},
	}

	srv := NewServer(
		pipelineHTTPForwardPermitWithBroker(t, brokenBroker),
		zap.NewNop(),
		WithHTTPForwardProxy(true),
		WithNetworkHardeningMode("enforce"),
		WithInferenceRoutes(routes),
	)
	srv.procResolver = testProcessResolver{id: &ProcessIdentity{PID: 123, Executable: "/bin/test"}}

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	proxyURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodPost, "http://inference.local/v1/chat/completions", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d body=%q", resp.StatusCode, body)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode deny payload: %v", err)
	}
	if payload["reason_code"] != reasons.InferenceAuthInjectionFailed {
		t.Fatalf("expected reason_code=%s, got %+v", reasons.InferenceAuthInjectionFailed, payload)
	}
	if brokenBroker.calls.Load() != 1 {
		t.Fatalf("expected exactly one broker fetch attempt, got %d", brokenBroker.calls.Load())
	}
}
