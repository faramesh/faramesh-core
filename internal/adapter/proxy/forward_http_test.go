package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

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
