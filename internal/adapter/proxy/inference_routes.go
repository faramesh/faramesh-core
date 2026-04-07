package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/credential"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// InferenceRoute defines route-level rewrite behavior for inference traffic.
type InferenceRoute struct {
	Name                string            `json:"name"`
	HostPattern         string            `json:"host_pattern"`
	PathPattern         string            `json:"path_pattern"`
	Methods             []string          `json:"methods,omitempty"`
	Upstream            string            `json:"upstream"`
	AuthType            string            `json:"auth_type,omitempty"` // bearer|header
	AuthHeader          string            `json:"auth_header,omitempty"`
	AuthToken           string            `json:"auth_token,omitempty"`
	AuthTokenEnv        string            `json:"auth_token_env,omitempty"`
	AuthBrokerToolID    string            `json:"auth_broker_tool_id,omitempty"`
	AuthBrokerOperation string            `json:"auth_broker_operation,omitempty"`
	AuthBrokerScope     string            `json:"auth_broker_scope,omitempty"`
	AuthBrokerRequired  bool              `json:"auth_broker_required,omitempty"`
	DefaultHeaders      map[string]string `json:"default_headers,omitempty"`
	ForceHeaders        map[string]string `json:"force_headers,omitempty"`
	ModelRewrite        string            `json:"model_rewrite,omitempty"`
}

func (s *Server) matchInferenceRoute(method, host, requestPath string) *InferenceRoute {
	method = strings.ToUpper(strings.TrimSpace(method))
	host = strings.ToLower(strings.TrimSpace(host))
	requestPath = strings.TrimSpace(requestPath)
	if requestPath == "" {
		requestPath = "/"
	}
	for i := range s.routes {
		route := &s.routes[i]
		if route == nil {
			continue
		}
		if !routeMatchesMethod(route, method) {
			continue
		}
		if !routeMatchesPattern(strings.ToLower(strings.TrimSpace(route.HostPattern)), host) {
			continue
		}
		if !routeMatchesPattern(strings.TrimSpace(route.PathPattern), requestPath) {
			continue
		}
		return route
	}
	return nil
}

func routeMatchesMethod(route *InferenceRoute, method string) bool {
	if route == nil {
		return false
	}
	if len(route.Methods) == 0 {
		return true
	}
	for _, allowed := range route.Methods {
		allowed = strings.ToUpper(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		if allowed == "*" || allowed == method {
			return true
		}
	}
	return false
}

func routeMatchesPattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, value)
	if err != nil {
		return value == pattern
	}
	return matched
}

func buildInferenceUpstreamURL(route *InferenceRoute, reqURL *url.URL) (string, error) {
	if route == nil {
		return "", fmt.Errorf("nil route")
	}
	base := strings.TrimSpace(route.Upstream)
	if base == "" {
		return "", fmt.Errorf("inference route %q has empty upstream", route.Name)
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse route upstream: %w", err)
	}
	if reqURL == nil {
		return baseURL.String(), nil
	}
	basePath := strings.TrimSuffix(baseURL.Path, "/")
	reqPath := "/" + strings.TrimPrefix(reqURL.Path, "/")
	baseURL.Path = basePath + reqPath
	baseURL.RawQuery = reqURL.RawQuery
	return baseURL.String(), nil
}

func rewriteModelInBody(body []byte, model string) ([]byte, bool) {
	model = strings.TrimSpace(model)
	if model == "" || len(body) == 0 {
		return body, false
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body, false
	}
	payload["model"] = model
	mutated, err := json.Marshal(payload)
	if err != nil {
		return body, false
	}
	return mutated, true
}

func applyInferenceRouteHeaders(outReq *http.Request, incoming http.Header, route *InferenceRoute) (string, error) {
	if outReq == nil || route == nil {
		return "", nil
	}

	for key, value := range route.DefaultHeaders {
		key = strings.TrimSpace(key)
		if key == "" || isUnsafeRouteHeaderKey(key) {
			continue
		}
		if incoming.Get(key) != "" || outReq.Header.Get(key) != "" {
			continue
		}
		outReq.Header.Set(key, value)
	}
	for key, value := range route.ForceHeaders {
		key = strings.TrimSpace(key)
		if key == "" || isUnsafeRouteHeaderKey(key) {
			continue
		}
		outReq.Header.Set(key, value)
	}

	token := strings.TrimSpace(route.AuthToken)
	if token == "" || strings.EqualFold(strings.TrimSpace(route.AuthType), "none") || strings.TrimSpace(route.AuthType) == "" {
		if strings.TrimSpace(route.AuthType) != "" && !strings.EqualFold(strings.TrimSpace(route.AuthType), "none") {
			return "", fmt.Errorf("%s: route auth token missing", reasons.InferenceAuthInjectionFailed)
		}
		return "", nil
	}

	switch strings.ToLower(strings.TrimSpace(route.AuthType)) {
	case "bearer":
		outReq.Header.Set("Authorization", "Bearer "+token)
	case "header":
		h := strings.TrimSpace(route.AuthHeader)
		if h == "" {
			return "", fmt.Errorf("%s: route auth_header is required for header auth", reasons.InferenceAuthInjectionFailed)
		}
		if isUnsafeRouteHeaderKey(h) {
			return "", fmt.Errorf("%s: route auth_header %q is not allowed", reasons.InferenceAuthInjectionFailed, h)
		}
		outReq.Header.Set(h, token)
	default:
		return "", fmt.Errorf("%s: unsupported route auth_type %q", reasons.InferenceAuthInjectionFailed, route.AuthType)
	}
	return token, nil
}

func isUnsafeRouteHeaderKey(key string) bool {
	k := strings.TrimSpace(key)
	if k == "" {
		return true
	}
	if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Connection") {
		return true
	}
	return isHopByHopHeader(k)
}

func (s *Server) resolveInferenceRouteAuthToken(ctx context.Context, agentID string, route *InferenceRoute) (string, func(), error) {
	if route == nil {
		return "", func() {}, nil
	}
	authType := strings.ToLower(strings.TrimSpace(route.AuthType))
	if authType == "" || authType == "none" {
		return "", func() {}, nil
	}

	token := strings.TrimSpace(route.AuthToken)
	if token != "" {
		return token, func() {}, nil
	}

	release := func() {}
	toolID := strings.TrimSpace(route.AuthBrokerToolID)
	operation := strings.TrimSpace(route.AuthBrokerOperation)
	scope := strings.TrimSpace(route.AuthBrokerScope)
	required := route.AuthBrokerRequired
	useBroker := required || toolID != "" || operation != "" || scope != ""

	if useBroker && s.pipeline != nil {
		if toolID == "" {
			toolID = HTTPForwardToolID
		}
		handle, err := s.pipeline.AcquireCredentialHandle(ctx, credential.FetchRequest{
			ToolID:    toolID,
			Operation: operation,
			Scope:     scope,
			AgentID:   agentID,
		}, required)
		if err != nil {
			return "", release, fmt.Errorf("%s: credential broker fetch failed: %w", reasons.InferenceAuthInjectionFailed, err)
		}
		if handle != nil {
			release = func() {
				_ = handle.Release(context.Background())
			}
			if handle.Credential != nil {
				token = strings.TrimSpace(handle.Credential.Value)
			}
		}
	}

	if token == "" && strings.TrimSpace(route.AuthTokenEnv) != "" {
		token = strings.TrimSpace(os.Getenv(route.AuthTokenEnv))
	}
	if token == "" && required {
		return "", release, fmt.Errorf("%s: route auth token missing", reasons.InferenceAuthInjectionFailed)
	}
	return token, release, nil
}

func bytesReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}
