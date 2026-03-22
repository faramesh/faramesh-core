package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/google/uuid"
)

// HTTPForwardToolID is the synthetic tool id for RFC 7230 absolute-form HTTP proxy requests
// (e.g. GET http://example.com/path HTTP/1.1). Policy matches on args.url and args.method.
const HTTPForwardToolID = "proxy/http"

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func isAbsoluteFormHTTPProxyRequest(r *http.Request) bool {
	return r.URL != nil && r.URL.Scheme != "" && r.URL.Host != ""
}

func stripHopByHop(dst, src http.Header) {
	for k, vs := range src {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func isHopByHopHeader(k string) bool {
	k = strings.TrimSpace(k)
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(k, h) {
			return true
		}
	}
	return false
}

func copyResponseHeaders(dst http.ResponseWriter, src http.Header) {
	for k, vs := range src {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vs {
			dst.Header().Add(k, v)
		}
	}
}

// handleHTTPForward implements a governed HTTP forward proxy for absolute-form request-targets.
func (s *Server) handleHTTPForward(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Scheme == "" || r.URL.Host == "" {
		http.Error(w, `{"error":"invalid proxy request"}`, http.StatusBadRequest)
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

	agentID := strings.TrimSpace(r.Header.Get("X-Faramesh-Agent-Id"))
	if agentID == "" {
		agentID = "proxy-forward"
	}

	targetURL := r.URL.String()
	car := core.CanonicalActionRequest{
		CallID:    uuid.New().String(),
		AgentID:   agentID,
		SessionID: agentID + "-proxy-http",
		ToolID:    HTTPForwardToolID,
		Args: map[string]any{
			"method": r.Method,
			"url":    targetURL,
		},
		Timestamp:        time.Now(),
		InterceptAdapter: "proxy",
	}

	decision := s.pipeline.Evaluate(car)
	switch decision.Effect {
	case core.EffectPermit, core.EffectShadow:
	default:
		if decision.Effect == core.EffectDefer {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":       "http forward deferred",
				"reason_code": reasons.Normalize(decision.ReasonCode),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "http forward denied",
			"reason_code": reasons.Normalize(decision.ReasonCode),
			"reason":      decision.Reason,
		})
		observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy http forward denied", observe.EventGovernDecision,
			zap.String("agent_id", agentID),
			zap.String("tool_id", HTTPForwardToolID),
			zap.String("url", targetURL),
			zap.String("effect", string(decision.Effect)),
			zap.String("reason_code", reasons.Normalize(decision.ReasonCode)),
		)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, `{"error":"bad upstream request"}`, http.StatusBadRequest)
		return
	}
	stripHopByHop(outReq.Header, r.Header)
	if r.ContentLength >= 0 {
		outReq.ContentLength = r.ContentLength
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 0}

	resp, err := client.Do(outReq)
	if err != nil {
		s.log.Warn("proxy http forward upstream error", zap.Error(err), zap.String("url", targetURL))
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.log.Debug("proxy http forward response copy ended", zap.Error(err))
	}

	observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy http forward", observe.EventGovernDecision,
		zap.String("agent_id", agentID),
		zap.String("tool_id", HTTPForwardToolID),
		zap.String("url", targetURL),
		zap.String("effect", string(decision.Effect)),
		zap.Int("status", resp.StatusCode),
		zap.String("policy_version", decision.PolicyVersion),
	)
}
