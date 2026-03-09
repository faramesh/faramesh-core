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
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/google/uuid"
)

// Server is the HTTP external authorization server (A3 adapter).
type Server struct {
	pipeline *core.Pipeline
	log      *zap.Logger
	httpSrv  *http.Server
}

// NewServer creates a new proxy adapter server.
func NewServer(pipeline *core.Pipeline, log *zap.Logger) *Server {
	s := &Server{
		pipeline: pipeline,
		log:      log,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/authorize", s.handleAuthorize)
	mux.HandleFunc("/v1/approve", s.handleApprove)
	mux.HandleFunc("/v1/defer/status", s.handleDeferStatus)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	s.httpSrv = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	return s
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

// Close shuts down the HTTP server.
func (s *Server) Close() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

// authorizeRequest is the JSON body for POST /v1/authorize.
type authorizeRequest struct {
	AgentID   string         `json:"agent_id"`
	SessionID string         `json:"session_id"`
	ToolID    string         `json:"tool_id"`
	Args      map[string]any `json:"args"`
	CallID    string         `json:"call_id"`
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

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
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
		CallID:           req.CallID,
		AgentID:          req.AgentID,
		SessionID:        req.SessionID,
		ToolID:           req.ToolID,
		Args:             req.Args,
		Timestamp:        time.Now(),
		InterceptAdapter: "proxy",
	}

	decision := s.pipeline.Evaluate(car)

	resp := authorizeResponse{
		Effect:        string(decision.Effect),
		RuleID:        decision.RuleID,
		ReasonCode:    decision.ReasonCode,
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
	w.Header().Set("X-Faramesh-Reason-Code", decision.ReasonCode)
	if decision.DeferToken != "" {
		w.Header().Set("X-Faramesh-Defer-Token", decision.DeferToken)
	}

	// HTTP 200 means the authorization request was processed.
	// The effect field in the body tells the caller the governance decision.
	// For Envoy ext_authz compatibility: return 200 with X-Faramesh-Effect header.
	// Envoy can be configured to check this header and deny forwarding on DENY/DEFER.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	s.log.Info("proxy authorized",
		zap.String("agent", req.AgentID),
		zap.String("tool", req.ToolID),
		zap.String("effect", string(decision.Effect)),
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
