package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
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

const maxForwardRequestBodyBytes int64 = 16 << 20

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
	connectionTokens := connectionHeaderTokens(src)
	for k, vs := range src {
		if isHopByHopHeader(k) || headerNameInSet(k, connectionTokens) {
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
	connectionTokens := connectionHeaderTokens(src)
	for k, vs := range src {
		if isHopByHopHeader(k) || headerNameInSet(k, connectionTokens) {
			continue
		}
		for _, v := range vs {
			dst.Header().Add(k, v)
		}
	}
}

func connectionHeaderTokens(headers http.Header) map[string]struct{} {
	out := make(map[string]struct{})
	if headers == nil {
		return out
	}
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			t := strings.ToLower(strings.TrimSpace(token))
			if t == "" {
				continue
			}
			out[t] = struct{}{}
		}
	}
	return out
}

func headerNameInSet(name string, allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		return false
	}
	_, ok := allowed[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func readBoundedBody(body io.Reader, maxBytes int64) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, true, nil
	}
	return raw, false, nil
}

// handleHTTPForward implements a governed HTTP forward proxy for absolute-form request-targets.
func (s *Server) handleHTTPForward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	statusCode := 0
	_, span := observe.StartOTLPSpan(r.Context(), "faramesh.proxy.http_forward")
	defer func() {
		if statusCode > 0 {
			observe.RecordProxyForwardOTLP(r.Context(), r.Method, statusCode, time.Since(start))
		}
		observe.EndOTLPSpan(span, nil)
	}()

	if r.URL == nil || r.URL.Scheme == "" || r.URL.Host == "" {
		statusCode = http.StatusBadRequest
		http.Error(w, `{"error":"invalid proxy request"}`, http.StatusBadRequest)
		return
	}

	if !s.allowIP(remoteIP(r.RemoteAddr)) {
		statusCode = http.StatusTooManyRequests
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

	host, port := hostPortFromURL(r.URL)
	if host == "" || port <= 0 {
		statusCode = http.StatusBadRequest
		http.Error(w, `{"error":"invalid upstream target"}`, http.StatusBadRequest)
		return
	}

	procIdentity, identityViolation := s.resolveProcessIdentity(r)
	if s.handleHardeningViolation(w, agentID, HTTPForwardToolID, identityViolation,
		zap.String("host", host),
		zap.Int("port", port),
		zap.String("path", r.URL.Path),
	) {
		statusCode = http.StatusForbidden
		return
	}

	dialHost, targetViolation := s.resolveEgressDialHost(host, port)
	if s.handleHardeningViolation(w, agentID, HTTPForwardToolID, targetViolation,
		zap.String("host", host),
		zap.Int("port", port),
		zap.String("path", r.URL.Path),
	) {
		statusCode = http.StatusForbidden
		return
	}
	if strings.TrimSpace(dialHost) == "" {
		dialHost = host
	}

	bodyBytes, tooLarge, err := readBoundedBody(r.Body, maxForwardRequestBodyBytes)
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	if tooLarge {
		statusCode = http.StatusRequestEntityTooLarge
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "request body too large",
			"reason_code": reasons.NetworkL7Deny,
		})
		return
	}

	targetURL := r.URL.String()
	args := map[string]any{
		"method":         r.Method,
		"url":            targetURL,
		"host":           host,
		"port":           port,
		"path":           r.URL.Path,
		"raw_query":      r.URL.RawQuery,
		"query":          querySnapshot(r.URL.Query()),
		"headers":        headersSnapshot(r.Header),
		"hardening_mode": string(s.hardening),
	}
	if procIdentity != nil {
		args["client_pid"] = procIdentity.PID
		args["client_executable"] = procIdentity.Executable
		args["client_executable_sha256"] = procIdentity.ExecutableSHA256
		args["process"] = map[string]any{
			"pid":               procIdentity.PID,
			"executable":        procIdentity.Executable,
			"executable_sha256": procIdentity.ExecutableSHA256,
		}
	}
	if targetViolation != nil && s.auditHardening() {
		args["hardening_audit_reason_code"] = targetViolation.Code
		args["hardening_audit_reason"] = targetViolation.Reason
	}
	if identityViolation != nil && s.auditHardening() {
		args["hardening_identity_audit_reason_code"] = identityViolation.Code
		args["hardening_identity_audit_reason"] = identityViolation.Reason
	}
	if strings.TrimSpace(dialHost) != "" {
		args["resolved_ip"] = dialHost
	}

	car := core.CanonicalActionRequest{
		CallID:           uuid.New().String(),
		AgentID:          agentID,
		SessionID:        agentID + "-proxy-http",
		ToolID:           HTTPForwardToolID,
		Args:             args,
		Timestamp:        time.Now(),
		InterceptAdapter: "proxy",
	}

	decision := s.pipeline.Evaluate(car)
	if s.shouldAuditPermitDecision(decision) {
		s.emitAuditDecisionBypass(agentID, HTTPForwardToolID, decision,
			zap.String("host", host),
			zap.Int("port", port),
			zap.String("path", r.URL.Path),
			zap.String("url", targetURL),
		)
		decision.Effect = core.EffectPermit
		decision.ReasonCode = reasons.NetworkL7AuditViolation
		if strings.TrimSpace(decision.Reason) == "" {
			decision.Reason = "audit mode bypassed blocking L7 decision"
		}
	}

	switch decision.Effect {
	case core.EffectPermit, core.EffectShadow, core.EffectShadowPermit:
	default:
		if decision.Effect == core.EffectDefer {
			statusCode = http.StatusForbidden
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":       "http forward deferred",
				"reason_code": networkPolicyReasonCode(decision),
			})
			return
		}
		reasonCode := networkPolicyReasonCode(decision)
		statusCode = http.StatusForbidden
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "http forward denied",
			"reason_code": reasonCode,
			"reason":      decision.Reason,
		})
		observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy http forward denied", observe.EventGovernDecision,
			zap.String("agent_id", agentID),
			zap.String("tool_id", HTTPForwardToolID),
			zap.String("url", targetURL),
			zap.String("effect", string(decision.Effect)),
			zap.String("reason_code", reasonCode),
		)
		return
	}

	route := s.matchInferenceRoute(r.Method, host, r.URL.Path)
	activeRoute := route
	egressHost := host
	egressPort := port
	inferenceModelRewriteApplied := false
	releaseRouteCredential := func() {}
	defer func() { releaseRouteCredential() }()
	if route != nil {
		routeCopy := *route
		token, release, routeErr := s.resolveInferenceRouteAuthToken(r.Context(), agentID, &routeCopy)
		if routeErr != nil {
			if s.handleHardeningViolation(w, agentID, HTTPForwardToolID, &hardeningViolation{
				Code:   reasons.InferenceAuthInjectionFailed,
				Reason: routeErr.Error(),
			},
				zap.String("route_name", routeCopy.Name),
				zap.String("host", host),
				zap.String("path", r.URL.Path),
			) {
				statusCode = http.StatusForbidden
				return
			}
		}
		routeCopy.AuthToken = token
		releaseRouteCredential = release
		activeRoute = &routeCopy

		routedURL, routeErr := buildInferenceUpstreamURL(activeRoute, r.URL)
		if routeErr != nil {
			statusCode = http.StatusBadGateway
			http.Error(w, `{"error":"invalid inference route"}`, http.StatusBadGateway)
			return
		}
		targetURL = routedURL
		rewrittenBody, rewriteApplied := rewriteModelInBody(bodyBytes, activeRoute.ModelRewrite)
		bodyBytes = rewrittenBody
		inferenceModelRewriteApplied = rewriteApplied
		args["route_name"] = activeRoute.Name
		args["route_upstream"] = activeRoute.Upstream
		if strings.TrimSpace(activeRoute.ModelRewrite) != "" {
			args["inference_model_rewrite"] = activeRoute.ModelRewrite
		}
		if inferenceModelRewriteApplied {
			args["inference_model_rewrite_applied"] = true
		}
		routedURLObj, parseErr := http.NewRequest(http.MethodGet, routedURL, nil)
		if parseErr != nil || routedURLObj.URL == nil {
			statusCode = http.StatusBadGateway
			http.Error(w, `{"error":"invalid inference route"}`, http.StatusBadGateway)
			return
		}
		egressHost, egressPort = hostPortFromURL(routedURLObj.URL)
		if egressHost == "" || egressPort <= 0 {
			statusCode = http.StatusBadGateway
			http.Error(w, `{"error":"invalid inference route target"}`, http.StatusBadGateway)
			return
		}
		routeDialHost, routeTargetViolation := s.resolveEgressDialHost(egressHost, egressPort)
		if s.handleHardeningViolation(w, agentID, HTTPForwardToolID, routeTargetViolation,
			zap.String("route_name", activeRoute.Name),
			zap.String("host", egressHost),
			zap.Int("port", egressPort),
			zap.String("path", r.URL.Path),
		) {
			statusCode = http.StatusForbidden
			return
		}
		if strings.TrimSpace(routeDialHost) != "" {
			dialHost = routeDialHost
			args["resolved_ip"] = routeDialHost
		}
	} else if strings.EqualFold(host, "inference.local") && s.hardeningEnabled() {
		if s.handleHardeningViolation(w, agentID, HTTPForwardToolID, &hardeningViolation{
			Code:   reasons.InferenceRouteNotFound,
			Reason: "inference.local request has no configured inference route",
		},
			zap.String("host", host),
			zap.String("path", r.URL.Path),
		) {
			statusCode = http.StatusForbidden
			return
		}
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytesReader(bodyBytes))
	if err != nil {
		statusCode = http.StatusBadRequest
		http.Error(w, `{"error":"bad upstream request"}`, http.StatusBadRequest)
		return
	}
	stripHopByHop(outReq.Header, r.Header)
	outReq.Header.Del("Authorization")
	outReq.Header.Del("X-API-Key")
	outReq.Header.Del("x-api-key")

	if activeRoute != nil {
		if _, routeErr := applyInferenceRouteHeaders(outReq, r.Header, activeRoute); routeErr != nil {
			if s.handleHardeningViolation(w, agentID, HTTPForwardToolID, &hardeningViolation{
				Code:   reasons.InferenceAuthInjectionFailed,
				Reason: routeErr.Error(),
			},
				zap.String("route_name", activeRoute.Name),
				zap.String("host", host),
				zap.String("path", r.URL.Path),
			) {
				statusCode = http.StatusForbidden
				return
			}
		}
	}

	if len(bodyBytes) > 0 {
		outReq.ContentLength = int64(len(bodyBytes))
	}

	if inferenceModelRewriteApplied {
		observe.Default.RecordHardeningOutcome(string(s.hardening), "inference_model_rewrite", reasons.InferenceModelRewriteApplied)
		observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy inference model rewrite applied", observe.EventGovernDecision,
			zap.String("agent_id", agentID),
			zap.String("tool_id", HTTPForwardToolID),
			zap.String("route_name", activeRoute.Name),
			zap.String("reason_code", reasons.InferenceModelRewriteApplied),
			zap.String("model_rewrite", activeRoute.ModelRewrite),
		)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if strings.TrimSpace(dialHost) != "" &&
		egressPort > 0 &&
		!strings.EqualFold(strings.TrimSpace(dialHost), strings.TrimSpace(egressHost)) {
		pinnedAddr := net.JoinHostPort(dialHost, strconv.Itoa(egressPort))
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, pinnedAddr)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 0}

	resp, err := client.Do(outReq)
	if err != nil {
		statusCode = http.StatusBadGateway
		s.log.Warn("proxy http forward upstream error", zap.Error(err), zap.String("url", targetURL))
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	statusCode = resp.StatusCode

	copyResponseHeaders(w, resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.log.Debug("proxy http forward response copy ended", zap.Error(err))
	}

	observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy http forward", observe.EventGovernDecision,
		zap.String("agent_id", agentID),
		zap.String("tool_id", HTTPForwardToolID),
		zap.String("host", egressHost),
		zap.Int("port", egressPort),
		zap.String("path", r.URL.Path),
		zap.String("hardening_mode", string(s.hardening)),
		zap.String("resolved_ip", dialHost),
		zap.String("url", targetURL),
		zap.String("effect", string(decision.Effect)),
		zap.Int("status", resp.StatusCode),
		zap.String("policy_version", decision.PolicyVersion),
	)
}
