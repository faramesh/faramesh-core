package proxy

import (
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

// ConnectToolID is the synthetic tool id used when evaluating HTTP CONNECT requests.
// Policy authors can permit or deny outbound tunnels with rules on this tool and args.target.
const ConnectToolID = "proxy/connect"

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.Host)
	if target == "" {
		target = strings.TrimSpace(r.URL.Host)
	}
	if target == "" {
		http.Error(w, `{"error":"missing connect target"}`, http.StatusBadRequest)
		return
	}
	host, port, err := parseConnectTarget(target)
	if err != nil {
		http.Error(w, `{"error":"invalid connect target (expected host:port)"}`, http.StatusBadRequest)
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

	procIdentity, identityViolation := s.resolveProcessIdentity(r)
	if s.handleHardeningViolation(w, agentID, ConnectToolID, identityViolation,
		zap.String("target", target),
		zap.String("host", host),
		zap.Int("port", port),
	) {
		return
	}

	dialHost, targetViolation := s.resolveEgressDialHost(host, port)
	if s.handleHardeningViolation(w, agentID, ConnectToolID, targetViolation,
		zap.String("target", target),
		zap.String("host", host),
		zap.Int("port", port),
	) {
		return
	}
	if strings.TrimSpace(dialHost) == "" {
		dialHost = host
	}

	args := map[string]any{
		"target":         target,
		"host":           host,
		"port":           port,
		"method":         http.MethodConnect,
		"path":           "",
		"query":          map[string]any{},
		"headers":        headersSnapshot(r.Header),
		"hardening_mode": string(s.hardening),
	}
	if strings.TrimSpace(dialHost) != "" {
		args["resolved_ip"] = dialHost
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

	car := core.CanonicalActionRequest{
		CallID:           uuid.New().String(),
		AgentID:          agentID,
		SessionID:        agentID + "-proxy-connect",
		ToolID:           ConnectToolID,
		Args:             args,
		Timestamp:        time.Now(),
		InterceptAdapter: "proxy",
	}

	decision := s.pipeline.Evaluate(car)
	if s.shouldAuditPermitDecision(decision) {
		s.emitAuditDecisionBypass(agentID, ConnectToolID, decision,
			zap.String("target", target),
			zap.String("host", host),
			zap.Int("port", port),
		)
		decision.Effect = core.EffectPermit
		decision.ReasonCode = reasons.NetworkL7AuditViolation
		if strings.TrimSpace(decision.Reason) == "" {
			decision.Reason = "audit mode bypassed blocking L7 decision"
		}
	}

	switch decision.Effect {
	case core.EffectPermit, core.EffectShadow, core.EffectShadowPermit:
		// proceed
	case core.EffectDefer:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "connect deferred; use ext_authz POST /v1/authorize for defer-capable flows",
			"reason_code": networkPolicyReasonCode(decision),
		})
		return
	default:
		reasonCode := networkPolicyReasonCode(decision)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "connect denied",
			"reason_code": reasonCode,
			"reason":      decision.Reason,
		})
		observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy connect denied", observe.EventGovernDecision,
			zap.String("agent_id", agentID),
			zap.String("tool_id", ConnectToolID),
			zap.String("target", target),
			zap.String("effect", string(decision.Effect)),
			zap.String("reason_code", reasonCode),
		)
		return
	}

	destConn, err := net.DialTimeout("tcp", net.JoinHostPort(dialHost, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, `{"error":"hijacking not supported"}`, http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		_, _ = io.Copy(destConn, clientConn)
	}()
	_, _ = io.Copy(clientConn, destConn)

	observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy connect tunnel", observe.EventGovernDecision,
		zap.String("agent_id", agentID),
		zap.String("tool_id", ConnectToolID),
		zap.String("target", target),
		zap.String("effect", string(decision.Effect)),
		zap.String("policy_version", decision.PolicyVersion),
	)
}
