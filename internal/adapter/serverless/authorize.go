// Package serverless provides HTTP handlers for mounting Faramesh governance in
// serverless and Cloud Run workloads (AWS Lambda + API Gateway, GCP Cloud Run, etc.).
//
// The JSON contract matches the proxy adapter POST /v1/authorize body so the same
// client integrations can call either a long-lived proxy or a stateless function.
package serverless

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/google/uuid"
)

// authorizeRequest mirrors internal/adapter/proxy authorize JSON.
type authorizeRequest struct {
	AgentID            string         `json:"agent_id"`
	SessionID          string         `json:"session_id"`
	ToolID             string         `json:"tool_id"`
	Args               map[string]any `json:"args"`
	CallID             string         `json:"call_id"`
	ExecutionTimeoutMS int            `json:"execution_timeout_ms,omitempty"`
}

type authorizeResponse struct {
	Effect        string `json:"effect"`
	RuleID        string `json:"rule_id,omitempty"`
	ReasonCode    string `json:"reason_code"`
	Reason        string `json:"reason,omitempty"`
	DeferToken    string `json:"defer_token,omitempty"`
	LatencyMs     int64  `json:"latency_ms"`
	PolicyVersion string `json:"policy_version,omitempty"`
}

// NewAuthorizeHandler returns an http.Handler that evaluates POST JSON bodies
// through the pipeline. InterceptAdapter is "serverless".
//
// Expected body matches POST /v1/authorize on the proxy adapter. Rate limiting
// and IP allowlists are left to API Gateway / Cloud Run; wrap this handler if needed.
func NewAuthorizeHandler(pipeline *core.Pipeline, log *zap.Logger) http.Handler {
	if log == nil {
		log = zap.NewNop()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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
			req.SessionID = req.AgentID + "-serverless-session"
		}

		car := core.CanonicalActionRequest{
			CallID:             req.CallID,
			AgentID:            req.AgentID,
			SessionID:          req.SessionID,
			ToolID:             req.ToolID,
			Args:               req.Args,
			ExecutionTimeoutMS: req.ExecutionTimeoutMS,
			Timestamp:          time.Now(),
			InterceptAdapter:   "serverless",
		}
		decision := pipeline.Evaluate(car)
		resp := authorizeResponse{
			Effect:        string(decision.Effect),
			RuleID:        decision.RuleID,
			ReasonCode:    reasons.Normalize(decision.ReasonCode),
			Reason:        decision.Reason,
			DeferToken:    decision.DeferToken,
			LatencyMs:     decision.Latency.Milliseconds(),
			PolicyVersion: decision.PolicyVersion,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Faramesh-Effect", string(decision.Effect))
		w.Header().Set("X-Faramesh-Rule-Id", decision.RuleID)
		w.Header().Set("X-Faramesh-Reason-Code", resp.ReasonCode)
		if decision.DeferToken != "" {
			w.Header().Set("X-Faramesh-Defer-Token", decision.DeferToken)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)

		observe.EmitGovernanceLog(log, zapcore.InfoLevel, "serverless authorize", observe.EventGovernDecision,
			zap.String("agent_id", req.AgentID),
			zap.String("session_id", req.SessionID),
			zap.String("call_id", req.CallID),
			zap.String("tool_id", req.ToolID),
			zap.String("effect", string(decision.Effect)),
			zap.String("reason_code", reasons.Normalize(decision.ReasonCode)),
			zap.String("rule_id", decision.RuleID),
		)
	})
}

// HealthHandler returns a minimal JSON health probe for load balancers.
func HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
