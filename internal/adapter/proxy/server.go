// Package proxy implements the A3 HTTP external authorization adapter.
//
// This adapter exposes an HTTP endpoint that Envoy, Kong, AWS API Gateway,
// and other proxies can call as an external authorization service. Every
// inbound request is evaluated by the Faramesh pipeline before the proxy
// forwards it.
//
// Endpoint: POST /v1/authorize
//
// Request body (JSON):
//
//	{
//	  "agent_id":   "payment-bot",
//	  "session_id": "sess-123",
//	  "tool_id":    "stripe/refund",
//	  "args":       {"amount": 500, "customer_id": "cust_abc"},
//	  "call_id":    "optional-idempotency-key"
//	}
//
// Response (200 OK):
//
//	{
//	  "effect":      "PERMIT",          // PERMIT | DENY | DEFER | SHADOW
//	  "rule_id":     "rule-003",
//	  "reason_code": "RULE_PERMIT",
//	  "reason":      "...",
//	  "defer_token": "a3f9b12c",        // only present on DEFER
//	  "latency_ms":  8,
//	  "policy_version": "abc123"
//	}
//
// Envoy external authorization integration (envoy.yaml):
//
//	http_filters:
//	  - name: envoy.filters.http.ext_authz
//	    typed_config:
//	      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
//	      http_service:
//	        server_uri:
//	          uri: http://faramesh:8080
//	          cluster: faramesh
//	          timeout: 0.25s
//	        authorization_request:
//	          headers_to_add:
//	            - key: x-faramesh-agent-id
//	              value: "%REQ(x-agent-id)%"
//
// Kong plugin integration: Use the external authorization plugin with
// config.http_service.url = "http://faramesh:8080/v1/authorize"
//
// Optional governed forward proxy:
//
//   - WithConnectProxy(true): RFC 7231 CONNECT; tool "proxy/connect", args.target (host:port).
//   - WithHTTPForwardProxy(true): RFC 7230 absolute-form HTTP (GET http://host/path …);
//     tool "proxy/http", args.method and args.url.
//
// Use --proxy-forward on faramesh serve to enable both; --proxy-connect enables CONNECT only.
package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/google/uuid"
	"go.uber.org/zap/zapcore"
)

// Server is the HTTP external authorization server (A3 adapter).
type Server struct {
	pipeline     *core.Pipeline
	log          *zap.Logger
	httpSrv      *http.Server
	mux          *http.ServeMux
	connectProxy bool
	forwardHTTP  bool
	rlMu         sync.Mutex
	rl           map[string]*rate.Limiter
}

// ServerOption configures NewServer.
type ServerOption func(*Server)

// WithConnectProxy enables HTTP CONNECT tunneling (forward proxy). CONNECT is intercepted
// before ServeMux routing because CONNECT uses an authority-form request-target.
func WithConnectProxy(enable bool) ServerOption {
	return func(s *Server) {
		s.connectProxy = enable
	}
}

// WithHTTPForwardProxy enables RFC 7230 absolute-form HTTP forwarding (classic HTTP proxy).
// Requests must use an absolute URI in the request-target; governance uses tool "proxy/http".
func WithHTTPForwardProxy(enable bool) ServerOption {
	return func(s *Server) {
		s.forwardHTTP = enable
	}
}

// NewServer creates a new proxy adapter server.
func NewServer(pipeline *core.Pipeline, log *zap.Logger, opts ...ServerOption) *Server {
	s := &Server{
		pipeline: pipeline,
		log:      log,
		rl:       make(map[string]*rate.Limiter),
	}
	for _, o := range opts {
		o(s)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/authorize", s.handleAuthorize)
	mux.HandleFunc("/v1/scan_output", s.handleScanOutput)
	mux.HandleFunc("/v1/approve", s.handleApprove)
	mux.HandleFunc("/v1/defer/status", s.handleDeferStatus)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	s.mux = mux

	readTO := 5 * time.Second
	writeTO := 5 * time.Second
	if s.connectProxy || s.forwardHTTP {
		readTO = 120 * time.Second
		writeTO = 120 * time.Second
	}
	s.httpSrv = &http.Server{
		Handler:      s.wrapHandler(mux),
		ReadTimeout:  readTO,
		WriteTimeout: writeTO,
		IdleTimeout:  120 * time.Second,
	}
	return s
}

// wrapHandler intercepts CONNECT and absolute-form HTTP proxy requests before ServeMux.
func (s *Server) wrapHandler(mux *http.ServeMux) http.Handler {
	if !s.connectProxy && !s.forwardHTTP {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect && s.connectProxy {
			s.handleConnect(w, r)
			return
		}
		if s.forwardHTTP && isAbsoluteFormHTTPProxyRequest(r) {
			s.handleHTTPForward(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Listen starts the HTTP server on the given address.
// addr should be in the form "host:port", e.g. ":8080" or "127.0.0.1:8080".
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy adapter listen on %q: %w", addr, err)
	}
	s.log.Info("proxy adapter listening", zap.String("addr", addr))
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("proxy adapter serve error", zap.Error(err))
		}
	}()
	return nil
}

// ListenTLS starts the HTTPS server on the given address.
func (s *Server) ListenTLS(addr, certFile, keyFile string, tlsConfig *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy adapter listen on %q: %w", addr, err)
	}
	s.httpSrv.TLSConfig = tlsConfig
	s.log.Info("proxy adapter listening (tls)", zap.String("addr", addr))
	go func() {
		if err := s.httpSrv.ServeTLS(ln, certFile, keyFile); err != nil && err != http.ErrServerClosed {
			s.log.Error("proxy adapter tls serve error", zap.Error(err))
		}
	}()
	return nil
}

// Close shuts down the HTTP server.
func (s *Server) Close() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

// Handler returns the root HTTP handler (tests, embedding, advanced wiring).
func (s *Server) Handler() http.Handler {
	return s.httpSrv.Handler
}

// authorizeRequest is the JSON body for POST /v1/authorize.
type authorizeRequest struct {
	AgentID            string         `json:"agent_id"`
	SessionID          string         `json:"session_id"`
	ToolID             string         `json:"tool_id"`
	Args               map[string]any `json:"args"`
	CallID             string         `json:"call_id"`
	ExecutionTimeoutMs int            `json:"execution_timeout_ms,omitempty"`
}

// authorizeResponse is the JSON body for 200 OK responses.
type authorizeResponse struct {
	Effect        string `json:"effect"`
	RuleID        string `json:"rule_id,omitempty"`
	ReasonCode    string `json:"reason_code"`
	Reason        string `json:"reason,omitempty"`
	DeferToken    string `json:"defer_token,omitempty"`
	LatencyMs     int64  `json:"latency_ms"`
	PolicyVersion string `json:"policy_version,omitempty"`
}

type scanOutputRequest struct {
	AgentID string `json:"agent_id"`
	ToolID  string `json:"tool_id"`
	Output  string `json:"output"`
}

type scanOutputResponse struct {
	Outcome         string `json:"outcome"`
	SanitizedOutput string `json:"sanitized_output,omitempty"`
	ReasonCode      string `json:"reason_code,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if !s.allowIP(remoteIP(r.RemoteAddr)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "rate_limited",
			"reason_code": reasons.SessionRollingLimit,
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB max
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	var req authorizeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.AgentID == "" {
		// Try to extract agent ID from headers (Envoy integration convenience).
		req.AgentID = r.Header.Get("X-Faramesh-Agent-Id")
	}
	if req.AgentID == "" {
		http.Error(w, `{"error":"agent_id is required"}`, http.StatusBadRequest)
		return
	}
	if req.ToolID == "" {
		http.Error(w, `{"error":"tool_id is required"}`, http.StatusBadRequest)
		return
	}
	if req.CallID == "" {
		req.CallID = uuid.New().String()
	}
	if req.SessionID == "" {
		req.SessionID = req.AgentID + "-proxy-session"
	}

	car := core.CanonicalActionRequest{
		CallID:             req.CallID,
		AgentID:            req.AgentID,
		SessionID:          req.SessionID,
		ToolID:             req.ToolID,
		Args:               req.Args,
		ExecutionTimeoutMS: req.ExecutionTimeoutMs,
		Timestamp:          time.Now(),
		InterceptAdapter:   "proxy",
	}

	decision := s.pipeline.Evaluate(car)

	resp := authorizeResponse{
		Effect:        string(decision.Effect),
		RuleID:        decision.RuleID,
		ReasonCode:    reasons.Normalize(decision.ReasonCode),
		Reason:        decision.Reason,
		DeferToken:    decision.DeferToken,
		LatencyMs:     decision.Latency.Milliseconds(),
		PolicyVersion: decision.PolicyVersion,
	}

	// Set Envoy-compatible response headers.
	// Envoy reads x-faramesh-effect to decide whether to forward the request.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Faramesh-Effect", string(decision.Effect))
	w.Header().Set("X-Faramesh-Rule-Id", decision.RuleID)
	w.Header().Set("X-Faramesh-Reason-Code", resp.ReasonCode)
	if decision.DeferToken != "" {
		w.Header().Set("X-Faramesh-Defer-Token", decision.DeferToken)
	}

	// HTTP 200 means the authorization request was processed.
	// The effect field in the body tells the caller the governance decision.
	// For Envoy ext_authz compatibility: return 200 with X-Faramesh-Effect header.
	// Envoy can be configured to check this header and deny forwarding on DENY/DEFER.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy authorized", observe.EventGovernDecision,
		zap.String("agent", req.AgentID),
		zap.String("tool", req.ToolID),
		zap.String("agent_id", req.AgentID),
		zap.String("session_id", req.SessionID),
		zap.String("call_id", req.CallID),
		zap.String("tool_id", req.ToolID),
		zap.String("effect", string(decision.Effect)),
		zap.String("reason_code", reasons.Normalize(decision.ReasonCode)),
		zap.String("rule_id", decision.RuleID),
		zap.String("policy_version", decision.PolicyVersion),
		zap.Int64("latency_ms", decision.Latency.Milliseconds()),
		zap.Duration("latency", decision.Latency),
	)
}

// approveRequest is the JSON body for POST /v1/approve.
type approveRequest struct {
	DeferToken string `json:"defer_token"`
	Approved   bool   `json:"approved"`
	Reason     string `json:"reason"`
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	var req approveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if err := s.pipeline.DeferWorkflow().Resolve(req.DeferToken, req.Approved, req.Reason); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) handleScanOutput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}
	var req scanOutputRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.ToolID == "" {
		http.Error(w, `{"error":"tool_id is required"}`, http.StatusBadRequest)
		return
	}
	res := s.pipeline.ScanOutput(req.ToolID, req.Output)
	resp := scanOutputResponse{
		Outcome:         string(res.Outcome),
		SanitizedOutput: res.Output,
		ReasonCode:      reasons.Normalize(res.ReasonCode),
		Reason:          res.Reason,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDeferStatus(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, `{"error":"token query parameter required"}`, http.StatusBadRequest)
		return
	}
	status, _ := s.pipeline.DeferWorkflow().Status(token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token, "status": string(status)})
}

func (s *Server) allowIP(ip string) bool {
	s.rlMu.Lock()
	limiter, ok := s.rl[ip]
	if !ok {
		limiter = rate.NewLimiter(rate.Limit(30), 60)
		s.rl[ip] = limiter
	}
	s.rlMu.Unlock()
	return limiter.Allow()
}

func remoteIP(remoteAddr string) string {
	host := remoteAddr
	if strings.Contains(remoteAddr, ":") {
		if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
			host = h
		}
	}
	if host == "" {
		return "unknown"
	}
	return host
}
