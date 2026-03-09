// Package sdk implements the A1 SDK adapter: a newline-delimited JSON
// protocol over a Unix domain socket. The Python/Node/Go SDK connects here
// to submit tool calls and receive governance decisions.
//
// Protocol:
//   Client → Server: {"type":"govern","call_id":"...","agent_id":"...","session_id":"...","tool_id":"...","args":{...}}\n
//   Server → Client: {"call_id":"...","effect":"PERMIT","rule_id":"...","reason":"...","reason_code":"...","defer_token":"...","latency_ms":11}\n
//
//   Client → Server: {"type":"poll_defer","agent_id":"...","defer_token":"..."}\n
//   Server → Client: {"defer_token":"...","status":"pending|approved|denied|expired"}\n
//
//   Client → Server: {"type":"approve_defer","defer_token":"...","approved":true,"reason":"..."}\n
//   Server → Client: {"ok":true}\n
//
//   Client → Server: {"type":"kill","agent_id":"..."}\n
//   Server → Client: {"ok":true}\n
//
//   Client → Server: {"type":"audit_subscribe"}\n
//   Server → Client: (stream of decision JSON objects, one per line, until connection closes)\n
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

	"github.com/faramesh/faramesh-core/internal/core"
)

const SocketPath = "/tmp/faramesh.sock"

// governRequest is the client → server message for a tool call.
type governRequest struct {
	Type      string         `json:"type"`
	CallID    string         `json:"call_id"`
	AgentID   string         `json:"agent_id"`
	SessionID string         `json:"session_id"`
	ToolID    string         `json:"tool_id"`
	Args      map[string]any `json:"args"`
}

// governResponse is the server → client message for a decision.
type governResponse struct {
	CallID     string `json:"call_id"`
	Effect     string `json:"effect"`
	RuleID     string `json:"rule_id"`
	Reason     string `json:"reason"`
	ReasonCode string `json:"reason_code"`
	DeferToken string `json:"defer_token,omitempty"`
	LatencyMs  int64  `json:"latency_ms"`
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

// Server listens on a Unix socket and serves governance requests.
type Server struct {
	pipeline *core.Pipeline
	log      *zap.Logger
	listener net.Listener
	// subscribers receive copies of every decision for audit tail.
	subsMu sync.Mutex
	subs   []chan core.Decision
}

// NewServer creates a new SDK socket server.
func NewServer(pipeline *core.Pipeline, log *zap.Logger) *Server {
	return &Server{
		pipeline: pipeline,
		log:      log,
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
func (s *Server) Subscribe() chan core.Decision {
	ch := make(chan core.Decision, 64)
	s.subsMu.Lock()
	s.subs = append(s.subs, ch)
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes a subscription channel.
func (s *Server) Unsubscribe(ch chan core.Decision) {
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

// Close shuts down the listener.
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) accept() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
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
		case "audit_subscribe":
			// This call blocks — it streams decisions until the connection closes.
			s.handleAuditSubscribe(conn)
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

	car := core.CanonicalActionRequest{
		CallID:           req.CallID,
		AgentID:          req.AgentID,
		SessionID:        req.SessionID,
		ToolID:           req.ToolID,
		Args:             req.Args,
		Timestamp:        time.Now(),
		InterceptAdapter: "sdk",
	}

	decision := s.pipeline.Evaluate(car)

	resp := governResponse{
		CallID:     req.CallID,
		Effect:     string(decision.Effect),
		RuleID:     decision.RuleID,
		Reason:     decision.Reason,
		ReasonCode: decision.ReasonCode,
		DeferToken: decision.DeferToken,
		LatencyMs:  decision.Latency.Milliseconds(),
	}
	writeJSON(conn, resp)

	// Fan out to audit subscribers.
	s.broadcast(decision)

	s.log.Info("governed",
		zap.String("agent", req.AgentID),
		zap.String("tool", req.ToolID),
		zap.String("effect", string(decision.Effect)),
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
	writeJSON(conn, map[string]any{"ok": true})
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

	for decision := range ch {
		writeJSON(conn, map[string]any{
			"effect":      string(decision.Effect),
			"rule_id":     decision.RuleID,
			"reason_code": decision.ReasonCode,
			"reason":      decision.Reason,
			"defer_token": decision.DeferToken,
			"latency_ms":  decision.Latency.Milliseconds(),
		})
	}
}

// broadcast sends a decision to all subscribed audit tail channels.
func (s *Server) broadcast(d core.Decision) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, ch := range s.subs {
		select {
		case ch <- d:
		default:
		}
	}
}

func writeJSON(conn net.Conn, v any) {
	b, _ := json.Marshal(v)
	b = append(b, '\n')
	_, _ = conn.Write(b)
}
