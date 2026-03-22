// Package sdk implements the A1 SDK adapter: a newline-delimited JSON
// protocol over a Unix domain socket. The Python/Node/Go SDK connects here
// to submit tool calls and receive governance decisions.
//
// Protocol:
//
//	Client → Server: {"type":"govern","call_id":"...","agent_id":"...","session_id":"...","tool_id":"...","args":{...}}\n
//	Server → Client: {"call_id":"...","effect":"PERMIT|DENY|DEFER","denial_token":"...","retry_permitted":false,"defer_token":"...","latency_ms":11}\n
//
//	Client → Server: {"type":"poll_defer","agent_id":"...","defer_token":"..."}\n
//	Server → Client: {"defer_token":"...","status":"pending|approved|denied|expired"}\n
//
//	Client → Server: {"type":"approve_defer","defer_token":"...","approved":true,"reason":"..."}\n
//	Server → Client: {"ok":true}\n
//
//	Client → Server: {"type":"kill","agent_id":"..."}\n
//	Server → Client: {"ok":true}\n
//
//	Client → Server: {"type":"audit_subscribe"}\n
//	Server → Client: (stream of decision JSON objects, one per line, until connection closes)\n
//
//	Client → Server: {"type":"callback_subscribe"}\n
//	Server → Client: (stream of callback event JSON objects, one per line, until connection closes)\n
//
//	Client → Server: {"type":"scan_output","agent_id":"...","tool_id":"...","output":"..."}\n
//	Server → Client: {"outcome":"PASS|REDACTED|DENIED|WARNED","sanitized_output":"...","reason_code":"...","reason":"..."}\n
package sdk

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
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

const SocketPath = "/tmp/faramesh.sock"

// governRequest is the client → server message for a tool call.
type governRequest struct {
	Type               string         `json:"type"`
	CallID             string         `json:"call_id"`
	AgentID            string         `json:"agent_id"`
	SessionID          string         `json:"session_id"`
	ToolID             string         `json:"tool_id"`
	Args               map[string]any `json:"args"`
	ExecutionTimeoutMs int            `json:"execution_timeout_ms,omitempty"`
}

// governResponse is the server → client message for a decision.
type governResponse struct {
	CallID         string `json:"call_id"`
	Effect         string `json:"effect"`
	DenialToken    string `json:"denial_token,omitempty"`
	RetryPermitted bool   `json:"retry_permitted,omitempty"`
	DeferToken     string `json:"defer_token,omitempty"`
	LatencyMs      int64  `json:"latency_ms"`
}

type auditEvent struct {
	Decision core.Decision
	AgentID  string
	ToolID   string
}

type callbackEvent struct {
	EventType string `json:"event_type"`
	Timestamp string `json:"timestamp"`

	// Decision lifecycle payload.
	CallID     string `json:"call_id,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	ToolID     string `json:"tool_id,omitempty"`
	Effect     string `json:"effect,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	ReasonCode string `json:"reason_code,omitempty"`
	RecordID   string `json:"record_id,omitempty"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	DeferToken string `json:"defer_token,omitempty"`

	// Defer resolution payload.
	Status   string `json:"status,omitempty"`
	Approved *bool  `json:"approved,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// pollDeferRequest is the client → server message for polling a DEFER.
type pollDeferRequest struct {
	Type       string `json:"type"`
	AgentID    string `json:"agent_id"`
	DeferToken string `json:"defer_token"`
}

// pollDeferResponse is the server → client message for a DEFER poll.
type pollDeferResponse struct {
	DeferToken string `json:"defer_token"`
	Status     string `json:"status"`
}

// approveRequest is the client → server message for approving/denying a DEFER.
type approveRequest struct {
	Type       string `json:"type"`
	DeferToken string `json:"defer_token"`
	Approved   bool   `json:"approved"`
	Reason     string `json:"reason"`
}

// scanOutputRequest is sent after the client executes a PERMIT'd tool; the server
// applies post_rules and returns sanitized output or a denial signal.
type scanOutputRequest struct {
	Type    string `json:"type"`
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

// Server listens on a Unix socket and serves governance requests.
type Server struct {
	pipeline *core.Pipeline
	log      *zap.Logger
	listener net.Listener
	// subscribers receive copies of every decision for audit tail.
	subsMu     sync.Mutex
	subs       []chan auditEvent
	cbSubs     []chan callbackEvent
	wg         sync.WaitGroup
	rlMu       sync.Mutex
	rl         map[string]*rate.Limiter
	connTokens chan struct{}
}

// NewServer creates a new SDK socket server.
func NewServer(pipeline *core.Pipeline, log *zap.Logger) *Server {
	return &Server{
		pipeline:   pipeline,
		log:        log,
		rl:         make(map[string]*rate.Limiter),
		connTokens: make(chan struct{}, 256),
	}
}

// Listen binds the Unix socket and starts accepting connections.
func (s *Server) Listen(socketPath string) error {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	s.listener = ln
	s.log.Info("SDK adapter listening", zap.String("socket", socketPath))
	go s.accept()
	return nil
}

// Subscribe returns a channel that receives a copy of every Decision.
// Used by audit tail.
func (s *Server) Subscribe() chan auditEvent {
	ch := make(chan auditEvent, 64)
	s.subsMu.Lock()
	s.subs = append(s.subs, ch)
	s.subsMu.Unlock()
	return ch
}

// SubscribeCallbacks returns a channel that receives SDK callback events.
func (s *Server) SubscribeCallbacks() chan callbackEvent {
	ch := make(chan callbackEvent, 64)
	s.subsMu.Lock()
	s.cbSubs = append(s.cbSubs, ch)
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes a subscription channel.
func (s *Server) Unsubscribe(ch chan auditEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for i, sub := range s.subs {
		if sub == ch {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// UnsubscribeCallbacks removes a callback subscription channel.
func (s *Server) UnsubscribeCallbacks(ch chan callbackEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for i, sub := range s.cbSubs {
		if sub == ch {
			s.cbSubs = append(s.cbSubs[:i], s.cbSubs[i+1:]...)
			close(ch)
			return
		}
	}
}

// Close shuts down the listener.
func (s *Server) Close() error {
	var closeErr error
	if s.listener != nil {
		closeErr = s.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		s.log.Warn("SDK adapter graceful drain timeout reached; closing anyway")
	}
	return closeErr
}

func (s *Server) accept() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		select {
		case s.connTokens <- struct{}{}:
		default:
			_ = conn.Close()
			s.log.Warn("SDK adapter connection limit reached; dropping connection")
			continue
		}
		s.wg.Add(1)
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.connTokens }()
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			writeJSON(conn, map[string]any{"error": "invalid JSON"})
			continue
		}

		var msgType string
		if raw, ok := msg["type"]; ok {
			_ = json.Unmarshal(raw, &msgType)
		}

		switch msgType {
		case "govern", "":
			s.handleGovern(conn, line)
		case "poll_defer":
			s.handlePollDefer(conn, line)
		case "approve_defer":
			s.handleApproveDefer(conn, line)
		case "kill":
			s.handleKill(conn, line)
		case "scan_output":
			s.handleScanOutput(conn, line)
		case "audit_subscribe":
			// This call blocks — it streams decisions until the connection closes.
			s.handleAuditSubscribe(conn)
			return
		case "callback_subscribe":
			// This call blocks — it streams callback events until the connection closes.
			s.handleCallbackSubscribe(conn)
			return
		default:
			writeJSON(conn, map[string]any{"error": "unknown type: " + msgType})
		}
	}
}

func (s *Server) handleGovern(conn net.Conn, line []byte) {
	var req governRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid govern request"})
		return
	}
	if req.AgentID != "" && !s.allowAgent(req.AgentID) {
		writeJSON(conn, map[string]any{
			"error":       "rate_limited",
			"reason_code": reasons.SessionRollingLimit,
		})
		return
	}
	if req.CallID == "" {
		req.CallID = uuid.New().String()
	}

	car := core.CanonicalActionRequest{
		CallID:             req.CallID,
		AgentID:            req.AgentID,
		SessionID:          req.SessionID,
		ToolID:             req.ToolID,
		Args:               req.Args,
		ExecutionTimeoutMS: req.ExecutionTimeoutMs,
		Timestamp:          time.Now(),
		InterceptAdapter:   "sdk",
	}

	decision := s.pipeline.Evaluate(car)

	resp := governResponse{
		CallID:         req.CallID,
		Effect:         string(decision.Effect),
		DenialToken:    decision.DenialToken,
		RetryPermitted: decision.RetryPermitted,
		DeferToken:     decision.DeferToken,
		LatencyMs:      decision.Latency.Milliseconds(),
	}
	writeJSON(conn, resp)

	// Fan out to audit subscribers.
	s.broadcast(auditEvent{Decision: decision, AgentID: req.AgentID, ToolID: req.ToolID})
	s.broadcastCallback(callbackEvent{
		EventType:  "decision",
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		CallID:     req.CallID,
		AgentID:    req.AgentID,
		SessionID:  req.SessionID,
		ToolID:     req.ToolID,
		Effect:     string(decision.Effect),
		RuleID:     decision.RuleID,
		ReasonCode: reasons.Normalize(decision.ReasonCode),
		RecordID:   decision.DPRRecordID,
		LatencyMs:  decision.Latency.Milliseconds(),
		DeferToken: decision.DeferToken,
	})

	observe.EmitGovernanceLog(s.log, zapcore.InfoLevel, "governed", observe.EventGovernDecision,
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

func (s *Server) handlePollDefer(conn net.Conn, line []byte) {
	var req pollDeferRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid poll_defer request"})
		return
	}
	status, _ := s.pipeline.DeferWorkflow().Status(req.DeferToken)
	if status != "pending" {
		var approved *bool
		switch status {
		case "approved":
			v := true
			approved = &v
		case "denied", "expired":
			v := false
			approved = &v
		}
		s.broadcastCallback(callbackEvent{
			EventType:  "defer_resolved",
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			AgentID:    req.AgentID,
			DeferToken: req.DeferToken,
			Status:     string(status),
			Approved:   approved,
		})
	}
	writeJSON(conn, pollDeferResponse{
		DeferToken: req.DeferToken,
		Status:     string(status),
	})
}

func (s *Server) handleApproveDefer(conn net.Conn, line []byte) {
	var req approveRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid approve_defer request"})
		return
	}
	reason := req.Reason
	if reason == "" {
		if req.Approved {
			reason = "approved via CLI"
		} else {
			reason = "denied via CLI"
		}
	}
	if err := s.pipeline.DeferWorkflow().Resolve(req.DeferToken, req.Approved, reason); err != nil {
		writeJSON(conn, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	status := "denied"
	if req.Approved {
		status = "approved"
	}
	approved := req.Approved
	s.broadcastCallback(callbackEvent{
		EventType:  "defer_resolved",
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		DeferToken: req.DeferToken,
		Status:     status,
		Approved:   &approved,
		Reason:     reason,
	})
	writeJSON(conn, map[string]any{"ok": true})
}

func (s *Server) handleScanOutput(conn net.Conn, line []byte) {
	var req scanOutputRequest
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid scan_output request"})
		return
	}
	if req.ToolID == "" {
		writeJSON(conn, map[string]any{"error": "tool_id is required"})
		return
	}
	if req.AgentID != "" && !s.allowAgent(req.AgentID) {
		writeJSON(conn, map[string]any{
			"error":       "rate_limited",
			"reason_code": reasons.SessionRollingLimit,
		})
		return
	}
	sr := s.pipeline.ScanOutput(req.ToolID, req.Output)
	writeJSON(conn, scanOutputResponse{
		Outcome:         string(sr.Outcome),
		SanitizedOutput: sr.Output,
		ReasonCode:      reasons.Normalize(sr.ReasonCode),
		Reason:          sr.Reason,
	})
}

func (s *Server) handleKill(conn net.Conn, line []byte) {
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, map[string]any{"error": "invalid kill request"})
		return
	}
	s.pipeline.SessionManager().Kill(req.AgentID)
	s.log.Warn("kill switch activated", zap.String("agent", req.AgentID))
	writeJSON(conn, map[string]any{"ok": true})
}

// handleAuditSubscribe streams every decision to this connection until it closes.
// The connection sends {"type":"audit_subscribe"} once, then receives a stream
// of decision JSON objects (one per line) until it disconnects.
func (s *Server) handleAuditSubscribe(conn net.Conn) {
	ch := s.Subscribe()
	defer s.Unsubscribe(ch)

	writeJSON(conn, map[string]any{"subscribed": true})

	for event := range ch {
		decision := event.Decision
		writeJSON(conn, map[string]any{
			"effect":      string(decision.Effect),
			"agent_id":    event.AgentID,
			"tool_id":     event.ToolID,
			"rule_id":     decision.RuleID,
			"reason_code": reasons.Normalize(decision.ReasonCode),
			"defer_token": decision.DeferToken,
			"latency_ms":  decision.Latency.Milliseconds(),
		})
	}
}

// handleCallbackSubscribe streams lifecycle callback events to this connection
// until it closes. This stream is optional and backward-compatible.
func (s *Server) handleCallbackSubscribe(conn net.Conn) {
	ch := s.SubscribeCallbacks()
	defer s.UnsubscribeCallbacks(ch)

	writeJSON(conn, map[string]any{"subscribed": true, "stream": "callbacks"})

	for event := range ch {
		writeJSON(conn, event)
	}
}

// broadcast sends a decision to all subscribed audit tail channels.
func (s *Server) broadcast(e auditEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// broadcastCallback sends callback events to all callback subscribers.
func (s *Server) broadcastCallback(e callbackEvent) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, ch := range s.cbSubs {
		select {
		case ch <- e:
		default:
		}
	}
}

func writeJSON(conn net.Conn, v any) {
	b, _ := json.Marshal(v)
	b = append(b, '\n')
	_, _ = conn.Write(b)
}

func (s *Server) allowAgent(agentID string) bool {
	s.rlMu.Lock()
	limiter, ok := s.rl[agentID]
	if !ok {
		limiter = rate.NewLimiter(rate.Limit(20), 40)
		s.rl[agentID] = limiter
	}
	s.rlMu.Unlock()
	return limiter.Allow()
}
