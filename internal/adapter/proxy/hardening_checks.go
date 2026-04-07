package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

type hardeningViolation struct {
	Code   string
	Reason string
}

var blockedControlPlanePorts = map[int]struct{}{
	2375:  {}, // Docker daemon (plain)
	2376:  {}, // Docker daemon (TLS)
	6443:  {}, // Kubernetes API server
	8500:  {}, // Consul API
	10250: {}, // Kubelet API
	10255: {}, // Kubelet readonly
	10257: {}, // kube-controller-manager
	10259: {}, // kube-scheduler
}

func (s *Server) hardeningEnabled() bool {
	return s.hardening == HardeningModeAudit || s.hardening == HardeningModeEnforce
}

func (s *Server) enforceHardening() bool {
	return s.hardening == HardeningModeEnforce
}

func (s *Server) auditHardening() bool {
	return s.hardening == HardeningModeAudit
}

func (s *Server) shouldAuditPermitDecision(decision core.Decision) bool {
	if !s.auditHardening() {
		return false
	}
	switch decision.Effect {
	case core.EffectDeny, core.EffectDefer:
		return true
	default:
		return false
	}
}

func (s *Server) emitAuditDecisionBypass(agentID, toolID string, decision core.Decision, fields ...zap.Field) {
	observe.Default.RecordHardeningOutcome(string(s.hardening), "audit_bypass", reasons.NetworkL7AuditViolation)
	observe.EmitGovernanceLog(s.log, zapcore.WarnLevel, "proxy L7 audit bypass", observe.EventGovernDecision,
		append([]zap.Field{
			zap.String("agent_id", agentID),
			zap.String("tool_id", toolID),
			zap.String("hardening_mode", string(s.hardening)),
			zap.String("reason_code", reasons.NetworkL7AuditViolation),
			zap.String("reason", "audit mode bypassed blocking L7 decision"),
			zap.String("original_effect", string(decision.Effect)),
			zap.String("original_reason_code", reasons.Normalize(decision.ReasonCode)),
		}, fields...)...,
	)
}

func networkPolicyReasonCode(decision core.Decision) string {
	rc := reasons.Normalize(decision.ReasonCode)
	switch rc {
	case reasons.UnmatchedDeny:
		return reasons.NetworkPolicyNoMatch
	case reasons.RuleDeny:
		return reasons.NetworkL7Deny
	default:
		return rc
	}
}

func (s *Server) handleHardeningViolation(w http.ResponseWriter, agentID, toolID string, violation *hardeningViolation, fields ...zap.Field) bool {
	if violation == nil {
		return false
	}
	if s.auditHardening() {
		observe.Default.RecordHardeningOutcome(string(s.hardening), "audit_violation", reasons.Normalize(violation.Code))
		observe.EmitGovernanceLog(s.log, zapcore.WarnLevel, "proxy hardening audit violation", observe.EventGovernDecision,
			append([]zap.Field{
				zap.String("agent_id", agentID),
				zap.String("tool_id", toolID),
				zap.String("hardening_mode", string(s.hardening)),
				zap.String("reason_code", reasons.Normalize(violation.Code)),
				zap.String("reason", violation.Reason),
			}, fields...)...,
		)
		return false
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":       "network hardening deny",
		"reason_code": reasons.Normalize(violation.Code),
		"reason":      violation.Reason,
	})
	observe.Default.RecordHardeningOutcome(string(s.hardening), "deny", reasons.Normalize(violation.Code))
	observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "proxy hardening deny", observe.EventGovernDecision,
		append([]zap.Field{
			zap.String("agent_id", agentID),
			zap.String("tool_id", toolID),
			zap.String("hardening_mode", string(s.hardening)),
			zap.String("reason_code", reasons.Normalize(violation.Code)),
			zap.String("reason", violation.Reason),
		}, fields...)...,
	)
	return true
}

func (s *Server) evaluateTargetHardening(host string, port int) *hardeningViolation {
	_, violation := s.resolveEgressDialHost(host, port)
	return violation
}

func (s *Server) resolveEgressDialHost(host string, port int) (string, *hardeningViolation) {
	if !s.hardeningEnabled() {
		return host, nil
	}
	if isBlockedControlPlanePort(port) {
		return "", &hardeningViolation{
			Code:   reasons.NetworkControlPlanePortBlock,
			Reason: fmt.Sprintf("egress port %d is blocked by control-plane protection", port),
		}
	}
	ips, err := resolveHostIPs(host)
	if err != nil || len(ips) == 0 {
		return host, nil
	}

	matchHost := normalizeHostForMatch(host)
	dialHost := ""
	var pendingViolation *hardeningViolation
	for _, ip := range ips {
		if dialHost == "" {
			dialHost = ip.String()
		}
		if isInternalIP(ip) {
			if !s.isPrivateEgressAllowed(matchHost, ip) {
				if pendingViolation == nil {
					pendingViolation = &hardeningViolation{
						Code:   reasons.NetworkSSRFBlock,
						Reason: fmt.Sprintf("target host %q resolves to internal address %s", host, ip.String()),
					}
				}
			}
		}
	}
	if dialHost == "" {
		return host, pendingViolation
	}
	return dialHost, pendingViolation
}

func normalizeHostForMatch(host string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
}

func (s *Server) isPrivateEgressAllowed(host string, ip net.IP) bool {
	if s.matchesAllowedPrivateHost(host) {
		return true
	}
	return s.matchesAllowedPrivateCIDR(ip)
}

func (s *Server) matchesAllowedPrivateHost(host string) bool {
	if host == "" {
		return false
	}
	for _, pattern := range s.privateHosts {
		candidate := normalizeHostForMatch(pattern)
		if candidate == "" {
			continue
		}
		if candidate == host {
			return true
		}
		matched, err := path.Match(candidate, host)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func (s *Server) matchesAllowedPrivateCIDR(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range s.privateCIDRs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) resolveProcessIdentity(r *http.Request) (*ProcessIdentity, *hardeningViolation) {
	if !s.hardeningEnabled() || s.procResolver == nil {
		return nil, nil
	}
	id, err := s.procResolver.Resolve(r)
	if err == nil {
		return id, nil
	}
	v := &hardeningViolation{
		Code:   reasons.NetworkIdentityUnresolved,
		Reason: fmt.Sprintf("unable to resolve client process identity: %v", err),
	}
	if s.auditHardening() {
		observe.EmitGovernanceLog(s.log, zapcore.WarnLevel, "proxy process identity unresolved (audit)", observe.EventGovernDecision,
			zap.String("hardening_mode", string(s.hardening)),
			zap.String("reason_code", reasons.Normalize(v.Code)),
			zap.String("reason", v.Reason),
		)
		return nil, nil
	}
	return nil, v
}

func parseConnectTarget(target string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(strings.TrimSpace(portRaw))
	if err != nil {
		return "", 0, err
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	return strings.ToLower(host), port, nil
}

func hostPortFromURL(u *url.URL) (string, int) {
	if u == nil {
		return "", 0
	}
	host := strings.ToLower(strings.Trim(strings.TrimSpace(u.Hostname()), "[]"))
	port := 0
	if p := strings.TrimSpace(u.Port()); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			port = parsed
		}
	}
	if port == 0 {
		switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
		case "https":
			port = 443
		case "http":
			port = 80
		}
	}
	return host, port
}

func headersSnapshot(h http.Header) map[string]any {
	out := make(map[string]any)
	for key, values := range h {
		k := strings.ToLower(strings.TrimSpace(key))
		if k == "" || len(values) == 0 {
			continue
		}
		out[k] = strings.TrimSpace(values[0])
	}
	return out
}

func querySnapshot(v url.Values) map[string]any {
	out := make(map[string]any)
	for key, values := range v {
		if len(values) == 0 {
			continue
		}
		if len(values) == 1 {
			out[key] = values[0]
			continue
		}
		items := make([]string, 0, len(values))
		for _, item := range values {
			items = append(items, item)
		}
		out[key] = items
	}
	return out
}

func isBlockedControlPlanePort(port int) bool {
	_, ok := blockedControlPlanePorts[port]
	return ok
}

func resolveHostIPs(host string) ([]net.IP, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.LookupIP(host)
}

func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 169 && v4[1] == 254 {
			return true
		}
	}
	return false
}
